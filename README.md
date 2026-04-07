# Auto-Hacker Agent 🤖🔓

**自主渗透测试智能体** — 以大语言模型（LLM）为核心的自动化渗透测试框架。

## 仓库状态

当前仓库已经整理为适合上传到 GitHub 和部署到 CVM 的状态：

- 不提交本地环境：`.venv/`、`.env`
- 不提交运行日志：`logs/`
- 不提交目标记忆缓存：`state/*.json`
- 不提交本地调试产物：`payload*.ser`
- 不提交本地下载的大体积二进制：`ysoserial*.jar`

如果你要重新下载工具或重新生成缓存，项目会在运行时自动创建对应目录或由部署脚本安装依赖。

## 📋 项目简介

本项目为智能渗透比赛而构建，智能体能够：

- 🔍 **自主信息收集** — 端口扫描、服务识别、Web 指纹
- 🐛 **自动漏洞发现** — SQL 注入、XSS、文件包含、命令注入等
- ⚔️ **智能漏洞利用** — SQLMap、Metasploit、自定义 Exploit
- 🏁 **自动 Flag 提取** — 正则匹配 `flag{}` 格式，自动提交
- 🧠 **LLM 驱动决策** — ReAct 环路，推理与行动交替执行

## 🏗️ 架构

```
├── main.py              # 程序入口
├── config.yaml          # 配置文件
├── agent/               # 核心智能体
│   ├── core.py          # ReAct 主循环
│   ├── llm.py           # LLM 抽象层（多模型切换）
│   ├── memory.py        # 上下文记忆管理
│   ├── planner.py       # 任务规划器
│   └── prompts.py       # 提示词模板
├── competition/         # 比赛平台交互
│   ├── api_client.py    # 官方 API 客户端
│   └── models.py        # 数据模型
├── skills/              # 🆕 预定义技能（节省 Token）
│   └── engine.py        # 技能引擎（10 个内置技能）
├── tools/               # 渗透工具封装
│   ├── skill_tool.py    # 🆕 技能调用接口
│   ├── shell.py         # Shell 命令执行
│   ├── nmap_tool.py     # Nmap 扫描
│   ├── web_tools.py     # Web 测试（curl/dirb/nikto）
│   ├── sqli_tool.py     # SQLMap 注入
│   ├── exploit_tool.py  # 漏洞利用
│   └── file_tools.py    # 文件操作
├── strategy/            # 渗透策略
│   ├── recon.py         # 信息收集策略
│   ├── vuln_scan.py     # 漏洞扫描策略
│   ├── exploit.py       # 漏洞利用策略
│   └── post_exploit.py  # 后渗透策略
└── utils/               # 工具函数
    ├── logger.py        # 日志系统
    ├── flag_parser.py   # Flag 提取
    └── network.py       # 网络工具
```

## 🧩 Skills 技能系统（省 Token 核心）

Skills 将多步操作封装为单次调用，**节省约 65% Token**:
- 无 Skills: 5 次 LLM 调用 × 2000 tokens ≈ 10,000 tokens
- 有 Skills: 1 次 LLM 调用 + 1 次汇总 ≈ 3,500 tokens

| 技能 | 说明 | 等效操作数 |
|------|------|-----------|
| `full_recon` | 全面信息收集（端口+服务+Web+敏感路径） | 6 步 |
| `web_recon` | Web 深度侦察（首页+Headers+泄露+指纹+管理后台） | 7 步 |
| `web_vuln_quick` | 快速漏洞探测（SQLi/LFI/RCE/SSRF/备份文件） | 5 步 |
| `flag_hunt` | 全盘搜索 Flag（find+grep 多路径） | 6 步 |
| `privesc_check` | Linux 提权检查（SUID/sudo/cron/capabilities） | 8 步 |
| `credential_harvest` | 凭据采集（配置文件/历史/env/SSH密钥） | 7 步 |
| `lateral_recon` | 内网发现（ping sweep+ARP+路由+端口扫描） | 5 步 |
| `smb_enum` | SMB 枚举（共享/用户/漏洞） | 4 步 |
| `db_enum` | 数据库探测（MySQL/Redis/Mongo/PG 未授权） | 5 步 |
| `deep_port_scan` | 深度扫描（全 TCP+UDP+漏洞脚本） | 3 步 |

## 📚 AboutSecurity 集成

项目已集成只读版 `AboutSecurity` 资源库，位置在 `resources/AboutSecurity/`。

- 不修改上游 `skills/**/SKILL.md`
- 通过 `aboutsecurity` 工具浏览外部方法论、Payload、字典和文档
- 适合在 LLM 决策前先检索相关打法，再结合现有 `skill` / `codegen` / 单工具执行

常见调用方式：

```json
{"action": "aboutsecurity", "action_input": {"action": "search_skills", "query": "sql injection"}}
{"action": "aboutsecurity", "action_input": {"action": "show_skill", "name": "sql-injection-methodology"}}
{"action": "aboutsecurity", "action_input": {"action": "search_resources", "module": "payload", "query": "xss"}}
```

## 🚀 快速开始

### 1. 环境准备（CVM 上执行）

```bash
# 推荐：Ubuntu 24 / 8C16G / 50G 使用 full profile
chmod +x setup_tools.sh
./setup_tools.sh --profile full

# 也支持更快或更重的预装档位
./setup_tools.sh --profile core
./setup_tools.sh --profile max

# 配置 API Key
cp .env.example .env
vim .env  # 填入你的 API Key
```

### 1.1 上传到 GitHub 前建议

```bash
git status
.venv/bin/pytest -q
.venv/bin/python main.py --self-check
```

如果这三步正常，再推到 GitHub，会比“边传边修”稳定很多。

### 2. 配置模型

编辑 `config.yaml`，设置 `llm.active_model` 为你想使用的模型：

```yaml
llm:
  active_model: "glm-4-plus"  # 或 deepseek-chat, qwen-max 等
```

### 3. 运行

```bash
# 正式比赛模式
source .venv/bin/activate
python3 main.py

# 调试模式 - 攻击单个目标
python3 main.py --debug --target 192.168.1.100 --port 80

# 指定模型运行
python3 main.py --model deepseek-chat

# 查看可用模型
python3 main.py --list-models
```

### 4. CVM 部署建议

推荐环境：

- Ubuntu 24.04
- 8C16G
- 50G 磁盘
- Python 3.10+

推荐部署流程：

```bash
git clone <your-repo-url>
cd autohackeragent
cp .env.example .env
vim .env
chmod +x setup_tools.sh
./setup_tools.sh --profile full
source .venv/bin/activate
python3 main.py --self-check
```

如果你需要更重的工具集，再用：

```bash
./setup_tools.sh --profile max
```

如果只是先验证项目框架能不能跑起来：

```bash
./setup_tools.sh --profile core
```

### 工具能力感知

Agent 启动时会自动探测当前机器上已安装的工具，并把结果注入提示词：
- 优先使用现场已安装工具
- 对缺失工具自动降级到可用方案
- 减少 `command not found` 带来的步数浪费

## ⚙️ 支持的模型

| 模型 | Provider | 说明 |
|------|----------|------|
| glm-4-plus | 智谱 AI | 推荐首选 |
| glm-4-flash | 智谱 AI | 快速推理 |
| milm | 小米 | 备选 |
| deepseek-chat | DeepSeek | 性价比高 |
| deepseek-reasoner | DeepSeek | 深度推理 |
| doubao-pro | 字节跳动 | 备选 |
| qwen-max | 阿里云 | 备选 |
| qwen-plus | 阿里云 | 快速推理 |
| ernie-4 | 百度 | 备选 |
| gpt-4o | OpenAI | 备选 |

> 💡 额度用尽时系统会自动切换到下一个可用模型

## 🏆 比赛赛区

| 赛区 | 名称 | 特点 |
|------|------|------|
| 第一赛区 | 识器·明理 | 20+ SRC 场景，Web 漏洞 |
| 第二赛区 | 洞见·虚实 | CVE、云安全、AI 漏洞 |
| 第三赛区 | 执刃·循迹 | 多层网络，OA 环境 |
| 第四赛区 | 铸剑·止戈 | 域渗透，企业内网 |

## 📊 计分规则

- 基础分 × (1 + 名次系数 + 提示系数)
- 第1名 +20%, 第2名 +10%, 第3名 +5%
- 查看提示 -10%
- 分值锁定：解出即锁定，不受后续影响

## 📝 日志

所有操作日志保存在 `logs/` 目录，包含：
- Agent 完整推理过程
- 工具调用及原始输出
- Flag 提交记录
- LLM Token 使用统计

## ⚠️ 注意事项

- 挑战时段禁止手动 SSH 登录 CVM
- 每天 3 次挑战机会，零点刷新
- 黑盒环境，无附件
- 严禁攻击比赛平台
- 公网云靶场默认不要猜本机私网 `LHOST`
- 未配置公网回连地址时，优先 `check`、in-band 验证、文件/HTTP 回显验证，而不是默认 reverse payload
