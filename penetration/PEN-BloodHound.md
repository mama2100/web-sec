# 域信息收集与 BloodHound

## 0x01 概述
进入域环境后第一件事不是乱打，而是"看清地图"：谁是什么权限、哪台机器有谁登录、从当前位置到域管的最短路径是什么。BloodHound 用图数据库把域内关系可视化，是域渗透的标准侦察工具。

## 0x02 前置条件
- 已有一个域内立足点（普通域用户即可开始收集）
- 本地装好 BloodHound + neo4j（社区版即可）

### BloodHound CE 版本说明
- 现行版本为 **BloodHound CE**（SpecterOps 重写版），与旧版 4.x 主要差异：
  - **数据采集器统一**：旧版 SharpHound 1.x 的采集包 CE 已无法导入，需配套新版 SharpHound v2；bloodhound.py 用新版本即可输出 CE 兼容格式
  - **neo4j 内嵌**：CE 自带图数据库，不再单独安装/启动 neo4j，一条命令起服务，Web UI 默认 `http://localhost:8080`，首次启动设置管理员账号
  - 界面全面 Web 化，旧版 GUI 的部分预置分析页被重构；Cypher 查询语法基本兼容
- 下载：GitHub Releases https://github.com/SpecterOps/BloodHound/releases

## 0x03 数据采集
### 1. SharpHound（Windows，C# 采集器）

```powershell
# exe 版全量采集
SharpHound.exe -c All

# 内存加载 ps1 版（少落地）
powershell -ep bypass
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
```

产出 zip 包，拷回本地导入 BloodHound。

### 2. bloodhound.py（Linux，走 LDAP 远程采集）

```bash
bloodhound-python -u user -p 'password' -d domain.local -ns 192.168.1.10 -c all --zip
```

无需落地 Windows，适合从 Linux 攻击机直接收集；`-ns` 指向域控/DNS。

### 3. 轻量/隐蔽场景
- 只采集关键项：`-c Session,LoggedOn,ACL,ObjectProps` 之类按需组合
- 分次采集降低流量峰值

## 0x04 导入与分析
1. 启动 neo4j，打开 BloodHound，拖入 zip
2. 左上角搜自己的用户名/机器名，右键 **Mark as Owned**
3. 常用内置查询：
   - `Shortest Paths to Domain Admins from Owned Principals`：从已控节点到域管的最短路径
   - `Find Principals with DCSync Rights`：找能直接 DCSync 的账户
   - `Find Kerberoastable Users`：kerberoasting 目标清单（接 [PEN-Kerberos](./PEN-Kerberos.md)）
   - `Find Computers with Unconstrained Delegation`：非约束委派机器
   - `Shortest Paths to High Value Targets`：高价值目标路径
4. 路径边的含义决定打法：`MemberOf`（组嵌套）、`AdminTo`（本地管理员）、`HasSession`（有高权限会话可抓）、`GenericAll/WriteDacl`（ACL 滥用）、`CanRDP` 等

## 0x05 自定义 Cypher 查询
内置查询不够用时，直接在查询框写 Cypher（语法同 Neo4j）。四个高频自定义查询：

```cypher
// 所有可 Kerberoast 的用户：有 SPN 的账户即可离线爆破（hashcat -m 13100）
MATCH (u:User {hasspn:true}) RETURN u

// 域管登录过的机器：拿下这些机器抓内存就有机会得到域管凭据
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}), (u)-[:HasSession]->(c:Computer) RETURN u,c

// 能 DCSync 的主体：控制其中任意账户即可导出全域 hash
MATCH p=(n)-[:GetChanges|GetChangesAll|GenericAll*1..]->(m:Domain) RETURN p

// 从当前用户到域对象的最短攻击路径
MATCH p=shortestPath((u:User {name:'USER@DOMAIN.LOCAL'})-[*1..]->(m:Domain)) RETURN p
```

要点：属性名区分大小写（`hasspn` 全小写）；组名/用户名要写 BloodHound 完整格式 `NAME@DOMAIN.LOCAL`；`shortestPath` 要求起点是单一确定节点。

## 0x06 手工收集备选（免 BloodHound 特征）
SharpHound 流量特征明显，EDR 严管环境改手工：

```powershell
# PowerView 常用
Get-DomainUser | select samaccountname
Get-DomainGroupMember "Domain Admins"
Get-DomainComputer | select dnshostname, operatingsystem
Find-LocalAdminAccess        # 扫自己在哪些机器有本地管理员
```

```bash
# Adfind（轻量 LDAP 查询）
Adfind.exe -b "DC=domain,DC=local" -f "objectcategory=person" samaccountname
```

### 免落地采集备选（ldapsearch / ADExplorer）
连 SharpHound/PowerView 都不落地时，用通用工具定向取数：

```bash
# 原生 ldapsearch 拉 SPN 账户清单 → 直接得到 Kerberoasting 目标清单（接 [PEN-Kerberos](./PEN-Kerberos.md) 0x05）
ldapsearch -x -H ldap://dc01.domain.local -D user@domain.local -w 'Passw0rd!' \
  '(&(objectclass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName
```

ADExplorer（Sysinternals）：GUI 直连域控，可把整个 AD 数据库快照成 `.dat` 离线带走慢慢翻，零脚本落地。

Windows 内建命令也可完成基础侦察，见 [PEN-WinCmd](./PEN-WinCmd.md)。

## 0x07 注意事项
- `Session` 收集（查每台机器谁登录着）噪声最大，隐蔽行动时可先跳过
- BloodHound 数据是"拍照"，域内变化快，打完关键节点后建议重新采集
- neo4j 默认监听本地，别把数据库端口暴露到公共网络
- 采集包里有全量域信息，妥善保管，打完即焚

## 0x08 参考
- [BloodHound](https://github.com/SpecterOps/BloodHound)
- [bloodhound.py](https://github.com/dirkjanm/BloodHound.py)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit)
- [BloodHound 官方文档（含 Cypher 与自定义查询指南）](https://bloodhound.specterops.io)
