---
name: ctf-source-audit
description: "CTF 挑战中的源码审计方法。当发现 .git 目录、.bak/.zip 备份、/proc/self/environ 泄露源码时使用。与真实代码审计不同——CTF 源码中的漏洞是故意设置的，通常只有 1-2 个关键点。先找危险函数（sink），再追溯输入（source）到该函数的路径"
metadata:
  tags: "ctf,source,audit,code review,源码审计,php,python,node,java,代码审计,SAST"
  category: "ctf"
---

# CTF 源码审计方法论

CTF 源码审计 ≠ 真实代码审计。区别：
- 真实审计：几万行代码，漏洞可能在任何地方
- CTF 审计：**几十到几百行代码，漏洞是故意设置的，通常很明显**

核心策略：**找危险函数**（sink），然后追溯输入（source）到危险函数的路径。

## ⛔ 深入参考（必读）

- PHP/Python/Node.js 完整危险函数清单、漏洞模式（弱比较/变量覆盖/条件竞争） → [references/dangerous-functions.md](references/dangerous-functions.md)

## Phase 1: 审计流程

### 1.1 快速定位危险函数

| 语言 | 命令执行 | 反序列化 | 模板注入 |
|------|----------|----------|----------|
| PHP | `system()` `eval()` `exec()` | `unserialize()` | N/A |
| Python | `os.system()` `eval()` `exec()` | `pickle.loads()` `yaml.load()` | `render_template_string()` |
| Node.js | `child_process.exec()` `eval()` | N/A | `__proto__` 原型链污染 |

→ 完整危险函数清单 → [references/dangerous-functions.md](references/dangerous-functions.md)

### 1.2 追踪数据流（sink → source）

1. **参数从哪来？** — `$_GET`, `request.args`, `req.body`
2. **有没有过滤？** — 搜 `filter`, `sanitize`, `escape`
3. **过滤能绕过吗？** — CTF 中通常有绕过（黑名单遗漏、双重编码、大小写）

### 1.3 常见 CTF 漏洞模式速查

- **PHP 弱比较**：`== '0e...'` → true | `md5([])===md5([])`
- **变量覆盖**：`extract($_GET)` / `parse_str()`
- **逻辑漏洞**：`admin ` (trailing space) | 金额负数

→ 完整模式和代码示例 → [references/dangerous-functions.md](references/dangerous-functions.md)

### 1.4 审计产出
1. 漏洞类型和位置（文件名+行号）
2. 利用方法（构造什么请求触发）
3. Flag 获取路径

## Phase 2: 常见漏洞模式详解

### 2.1 PHP 数组绕过
- md5(array) 返回 NULL，可绕过比较
- GET 参数数组语法：`a[]=1&b[]=2`

### 2.2 变量覆盖
- register_globals 历史漏洞及类似原理（extract/parse_str）
