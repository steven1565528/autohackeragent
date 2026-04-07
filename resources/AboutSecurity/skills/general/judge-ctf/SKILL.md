---
name: judge-ctf
description: "CTF 夺旗决策 Agent 评估清单。用于评估 CTF 挑战是否完成（flag 是否找到），分析未找到 flag 的原因，并给出精准的 flag 获取指导。当 CTF 攻击陷入僵局、需要判断是否遗漏攻击路径、或已获取疑似 flag 需要验证格式时使用"
metadata:
  tags: "judge,评估,ctf,flag,决策"
  category: "general"
---

# CTF 夺旗评估清单

## 唯一成功标准

**flag{...} 是否已找到？**
- 在 agent 输出日志中搜索 `flag{`
- 在 evidence 文件中搜索 `flag{`
- 在 vulns.json 的 detail 字段中搜索

找到 → complete: true，无需进一步评估。

## 未找到 Flag 时的诊断

### Step 1: 漏洞是否已发现？

```
if 漏洞数 == 0:
    → 侦察不足，建议扩大攻击面
    feedback: "未发现任何漏洞，建议：
      1. 仔细检查所有 HTTP 响应中的隐藏线索
      2. 尝试目录爆破发现隐藏端点
      3. 检查页面源码中的注释和隐藏参数
      4. 尝试常见默认凭据登录"
```

### Step 2: 漏洞是否已利用？

```
if 有漏洞但未利用:
    → 漏洞利用不足
    feedback: "发现了 {vuln_type}，但未利用获取 flag。建议：
      - SQLi: 用 UNION SELECT 读取数据库表，找 flag 表
      - LFI: 读取 /flag.txt, /home/*/flag, /var/www/flag
      - RCE: find / -name 'flag*' 2>/dev/null
      - IDOR: 遍历所有 id 值，检查每个响应中的 flag"
```

### Step 3: 利用了但没拿到 flag？

```
if 漏洞已利用但无 flag:
    → flag 位置可能不在预期位置
    feedback: "漏洞已利用但未找到 flag，建议：
      1. 数据库搜索: SELECT * FROM flags / 搜索所有表
      2. 文件搜索: find / grep -r 'flag{' / env | grep FLAG
      3. 检查响应头: curl -v 看 HTTP headers
      4. 检查隐藏页面: 用已获得的权限访问 /admin, /dashboard
      5. 检查源码: 反编译/查看应用源码中的硬编码 flag"
```

## CTF 常见出题模式

Judge 应了解这些模式来给出精准反馈：

| 漏洞类型 | Flag 通常在哪 |
|---------|-------------|
| SQL 注入 | 数据库某个表的某个字段 |
| LFI/路径遍历 | /flag.txt 或 /etc/flag 或应用目录下 |
| RCE/命令注入 | 文件系统中，需要 find/grep |
| IDOR | 某个特定 id 的资源内容里 |
| 反序列化 | 获取 RCE 后在文件系统中 |
| SSRF | 内网服务的响应中 |
| XSS | 通常不直接给 flag，除非有 admin bot |
| 信息泄露 | 源码注释、备份文件、配置文件中 |

## 反馈精准度要求

**禁止**泛泛的反馈如"继续测试"、"更深入地挖掘"。

**必须**给出具体的：
1. 利用哪个已发现的漏洞
2. 具体的利用步骤（payload 级别）
3. flag 最可能在哪里
