# 云上攻防速查

## 0x01 概述
云上资产的攻防围绕三个核心：**AKSK 凭证、元数据服务（metadata）、对象存储**。拿到任意一个，往往就能接管整个云账号下的资源。

## 0x02 前置条件
- 已获取以下之一：AKSK、实例临时凭证、SSRF 入口、控制台低权限账号
- 明确目标云厂商（阿里云/腾讯云/AWS/华为云），各家 API 与 metadata 地址不同

## 0x03 AKSK 泄露来源
- GitHub/Gitee 代码搜索：`AccessKeyId`、`LTAI`（阿里云前缀）、`AKID`（腾讯云前缀）
- 前端 JS、小程序/APK 反编译（见 [EXP-InfoLeak](../exp/EXP-InfoLeak.md)）
- 配置文件泄露：`.env`、`application.yml`（任意文件读取 -> [EXP-FileRead](../exp/EXP-FileRead.md)）
- SSRF 打 metadata（下节）

## 0x04 元数据服务（metadata）
云厂商给实例提供元数据 API，其中**临时凭证**最值钱：

| 厂商 | 地址 | 备注 |
| --- | --- | --- |
| AWS | `http://169.254.169.254/latest/meta-data/` | IMDSv2 需先 PUT 取 token |
| 阿里云 | `http://100.100.100.200/latest/meta-data/` | `ram/security-credentials/<角色名>` |
| 腾讯云 | `http://metadata.tencentyun.com/latest/meta-data/` | `cam/security-credentials/<角色名>` |
| 华为云 | `http://169.254.169.254/openstack/latest/meta_data.json` | |

打法：SSRF（见 [EXP-SSRF](../exp/EXP-SSRF.md)）请求 metadata -> 拿到临时 AKSK -> 走官方 API 接管资源。

## 0x05 凭证利用
### 1. 行云管家/CF 等集成工具
- [CF 云环境利用框架](https://github.com/teamssix/cf)：一键查看权限、执行命令、对象存储操作
- [aliyun-accesskey-Tools](https://github.com/mrknow001/aliyun-accesskey-Tools)：阿里云 ECS 执行命令

### 2. 官方 CLI（最通用）

```bash
# 配置凭证
aliyun configure --mode AK --access-key-id xxx --access-key-secret xxx
# 列出 ECS 实例
aliyun ecs DescribeInstances
# 向实例下发命令（需云助手权限）
aliyun ecs RunCommand --Type RunShellScript --CommandContent "id" --InstanceId.1 i-xxxx
```

```bash
# AWS
aws configure
aws sts get-caller-identity      # 先看自己是谁、有什么权限
aws s3 ls                        # 列存储桶
```

```bash
# 腾讯云 tccli
pip install tccli
tccli configure                                  # 交互式写入 SecretId / SecretKey / region
tccli cam ListUsers                              # 列 CAM 用户，探测权限边界
tccli cvm DescribeInstances --region ap-guangzhou
# 使用 metadata / assume-role 拿到的临时凭证时追加 --Token 参数
tccli sts GetCallerIdentity --SecretId x --SecretKey x --Token x
```

```bash
# 华为云 KooCLI（hcloud）
hcloud configure          # 交互式配置 AK / SK / 区域 / 项目
hcloud IAM ListUsers      # 列 IAM 用户
hcloud ECS NovaListServers  # 列 ECS 实例
```

### 3. 权限探测
凭证到手第一件事：确认权限边界。用 `cf alibaba perm`、AWS 的 `enumerate-iam` 或逐个 API 试探。

## 0x06 对象存储（OSS/S3）
- **桶遍历**：权限配置公开读时直接 `aws s3 ls s3://bucket --no-sign-request`，阿里云 OSS 访问 `https://<bucket>.oss-cn-xxx.aliyuncs.com/?prefix=`
- **公开写**：上传 webshell 到静态站点桶、覆盖 JS 投毒
- **桶接管**：子域指向已删除的桶，注册同名桶接管流量

## 0x07 Kubernetes 攻击面
K8s 集群把大量高权限端口直接暴露在 Node 网络里，一个配置失误即可接管整个集群。核心链路：**未授权 API -> 读 Secret / 拿 SA Token -> 创建特权 Pod -> 逃逸到宿主机**。

### 1. 攻击入口
| 入口 | 端口/位置 | 判定与利用 |
| --- | --- | --- |
| apiserver 未授权 | 8080（--insecure-port）/ 6443 | 8080 匿名可直接 kubectl 操作；6443 测试是否放行 `system:anonymous` |
| kubelet API | 10250 | 未授权可在任意容器内执行命令、读取 Pod 内文件 |
| etcd | 2379 | 未授权可读全部 Secret/ConfigMap（含集群管理凭证） |
| Dashboard | NodePort / LoadBalancer 暴露 | 老版本跳过登录；新版可用默认 ServiceAccount 权限越权 |
| docker API | 2375 | 未授权 docker API，直接挂载宿主机根目录逃逸 |
| Service Account Token | Pod 内 `/var/run/secrets/kubernetes.io/serviceaccount/token` | RCE 进 Pod 后读取，Token 即集群内身份，RBAC 配置松即可横向 |

### 2. 常见利用命令
```bash
kubectl get pods -s http://target:8080         # 8080 未授权
curl -k https://ip:6443/api/v1/nodes           # 6443 匿名
kubectl --token=xxx get secrets -n kube-system # SA token 利用
# 创建特权 Pod 逃逸到宿主机
kubectl apply -f privileged-pod.yaml
```

### 3. kubeletctl
[kubeletctl](https://github.com/cyberark/kubeletctl) 一把梭 kubelet 10250：
```bash
kubeletctl pods --server ip:10250                            # 列出节点上的 Pod
kubeletctl run "id" --server ip:10250 -p <pod> -c <container>  # 在容器内执行命令
kubeletctl scan rce --server ip:10250                        # 批量探测可 RCE 的 kubelet
```

### 4. Pod 逃逸一句话清单
拿到 Pod 权限后优先检查：`privileged: true`、`hostPID`、`hostPath` 挂 `/`、挂载 `/var/run/docker.sock` —— 任一命中即可直接逃逸到宿主机。逃逸利用细节见主仓库 [README](../README.md)「Docker&Sandbox 逃逸」章节与 [Container-escape-exps](https://github.com/duowen1/Container-escape-exps)。

## 0x08 权限维持与横向
- 创建新 AK（`CreateAccessKey`）、新建 RAM 用户并授权 -> 隐蔽持久化
- 向已有 RAM 用户附加高权限策略
- 利用云函数/自动化任务做定时回连
- 通过 VPC 对等连接、云联网摸内网（云内网与传统内网打法衔接）

## 0x09 注意事项
- 云 API 调用全部有日志（操作审计/CloudTrail），动作越大暴露越快
- 临时凭证有效期短（通常 1-6 小时），拿到手尽快评估
- `get-caller-identity` 这类"无害"探测也会留痕，别以为探测不告警
- 部分云厂商对境外 IP 调用 API 有额外风控

## 0x0A 参考
- [CF 云环境利用框架](https://github.com/teamssix/cf)
- [T Wiki - 云安全](https://wiki.teamssix.com/cloudsecurity/)
- [从零开始的 Kubernetes 攻防](https://github.com/neargle/my-re0-k8s-security)
- [kubeletctl](https://github.com/cyberark/kubeletctl)
- [腾讯云 CLI（tccli）官方文档](https://cloud.tencent.com/document/product/440/6176)
- [华为云命令行工具 KooCLI](https://support.huaweicloud.com/cli/index.html)
