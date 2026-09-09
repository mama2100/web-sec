# 认证与会话机制（原理篇）

## 定位
本篇是原理层文档：讲清楚 Web 应用"怎么记住你是谁"，以及这套机制的边界在哪里。利用手法不展开，分别指向 exp/ 对应篇目。

## 认证 vs 授权
理解大量漏洞的总钥匙：
- **认证（Authentication）**：你是谁？——登录、Token、证书
- **授权（Authorization）**：你能做什么？——角色、权限、资源归属

绝大多数越权漏洞，都是因为系统把两件事混为一谈：验了"登录了没有"，没验"这资源是不是你的"。利用见 [EXP-IDOR](../exp/EXP-IDOR.md)。

## Cookie + Session 模式
### 工作流程
1. 登录成功，服务端创建 Session（存内存/Redis），下发 `Set-Cookie: SESSIONID=xxx`
2. 浏览器之后每次请求自动携带 Cookie
3. 服务端按 SESSIONID 查 Session，恢复身份

### Cookie 关键属性
| 属性 | 作用 | 安全意义 |
| --- | --- | --- |
| `HttpOnly` | JS 不可读 | 缓解 XSS 盗 Cookie（不能缓解 CSRF） |
| `Secure` | 仅 HTTPS 传输 | 防明文嗅探 |
| `SameSite` | 跨站携带策略（Strict/Lax/None） | 现代 CSRF 防线，见 [EXP-CSRF](../exp/EXP-CSRF.md) |
| `Domain` / `Path` | 作用范围 | 设置过宽会被子域滥用，过窄会丢失登录态 |
| `Expires/Max-Age` | 有效期 | 长有效期 + 无服务端失效 = 登出是假的 |

### 经典攻击面
- **会话固定（Session Fixation）**：登录前后 SESSIONID 不变，攻击者先塞一个 ID 给受害者
- **会话预测**：ID 生成弱随机（时间戳、自增），见 [VUL-Crypto](./VUL-Crypto.md)
- **登出不失效**：服务端只清前端 Cookie，Session 仍可复用
- **子域会话共享**：`Domain=.target.com` 时子域 XSS 可读写主站 Cookie

## Token / JWT 模式
### 与 Session 的本质区别
- Session：状态在服务端，可撤销、可控制，但每次查存储
- JWT：状态在客户端（自包含签名），服务端无状态、不可单点撤销，靠短有效期 + 刷新机制兜底

### 边界认知
- JWT 签名只保证完整性，**payload 不保密**
- "退出登录"对 JWT 只是前端删除，Token 到期前仍有效（除非维护黑名单，那就退化回有状态了）
- 利用手法（伪造、混淆、爆破）见 [EXP-JWT](../exp/EXP-JWT.md)

## 会话管理进阶（防御侧设计）
- **固定过期 vs 滑动过期**：固定过期 = 登录后 N 分钟绝对失效（安全上限明确）；滑动过期 = 每次活动自动续期（体验好但可能"永不掉线"）。安全敏感场景必须给滑动过期叠加绝对过期上限，否则一次窃取终身有效
- **并发会话控制**：同账号是否允许多端同时在线要明确定义；"新登录踢旧会话"既是策略也是止损手段（盗号后旧设备会话即刻失效）
- **会话超时**：闲置超时（idle timeout）与绝对超时分开配置；超时后必须服务端真正失效并重新认证，不能只弹回登录页而旧 Session 依然可用
- **退出全端失效**：登出 = 服务端销毁 Session（或 JWT 进黑名单）+ 清 Cookie + 吊销 refresh_token + 踢出其他在线端——只删前端 Cookie 是假登出（对应上文"登出不失效"）
- **改密/敏感操作后强制重置所有会话**：防止旧会话（尤其被盗的那台设备）在改密后继续存活

## OAuth 2.0 / OIDC
常用于第三方登录（"微信登录""Google 登录"）。

### 授权码模式（Authorization Code）完整流程
四个角色：资源拥有者（用户）/ 客户端（第三方应用）/ 授权服务器 / 资源服务器。

```
(1) 用户点击"用 XX 登录"
        用户 ──────────────────────────▶ 客户端

(2) 客户端 302 跳转授权页，携带 client_id / redirect_uri / scope / state / code_challenge
        客户端 ────────────────────────▶ 授权服务器

(3) 授权服务器展示登录 + 授权同意页
        授权服务器 ────────────────────▶ 用户

(4) 用户登录并点击"同意授权"
        用户 ──────────────────────────▶ 授权服务器

(5) 授权服务器 302 回调：redirect_uri?code=xxx&state=yyy
        授权服务器 ────────────────────▶ 客户端

(6) 客户端后端拿 code + client_secret + code_verifier 请求 /token 换令牌
        客户端 ────────────────────────▶ 授权服务器

(7) 授权服务器校验通过，返回 access_token（+ refresh_token）
        授权服务器 ────────────────────▶ 客户端

(8) 客户端携带 access_token 调用用户信息 API
        客户端 ────────────────────────▶ 资源服务器

(9) 资源服务器返回用户资料，客户端据此完成本地登录/账号绑定
        资源服务器 ────────────────────▶ 客户端
```

安全关键点：code 必须一次性 + 短时效；`state` 防 (5) 步回调 CSRF；`client_secret` 只在 (6) 步后端使用，永不下发前端；access_token 不出现在 URL / 前端存储。

### PKCE（RFC 7636）：防授权码截获
- SPA、移动端这类**公开客户端存不住 client_secret**：(5)→(6) 之间 code 落在 URL/自定义 scheme 里，恶意 App 抢注 scheme、Referer 泄露都可能截走 code，拿到即可换 token
- 机制：客户端先生成随机 `code_verifier`，其 SHA-256 即 `code_challenge`，随 (2) 步授权请求发出；(6) 步换 token 时必须出示原始 `code_verifier`，授权服务器校验哈希一致才发令牌
- 效果：截获 code 的人拿不出 verifier，第 (6) 步必然失败——**code 被截获也无法兑换**
- OAuth 2.1 已要求所有客户端（含机密客户端）强制 PKCE

常见误用（漏洞高发区）：
- **缺 `state` 参数**：回调可被 CSRF，攻击者把自己的账号绑给受害者
- **`redirect_uri` 校验不严**：开放重定向 + 授权码/Token 泄露
- **隐式模式（implicit）**：Token 直接出现在 URL，易泄露（历史原因仍在用）
- **绑定逻辑缺陷**：第三方账号与本地账号绑定环节可越权

## SSO / 单点登录
- CAS、SAML、OIDC 都是"一处认证，多处信任"
- 攻击面：票据伪造（SAML 签名绕过）、回调投毒、跨系统权限提升
- 一处失守 -> 全线失守，域渗透里的 SSO 与 Kerberos 同理（见 [PEN-Kerberos](../penetration/PEN-Kerberos.md)）

### SAML 攻击面（重点）
SAML 流程：IdP 认证后签发**带签名的 SAML Assertion**（内含 NameID = 用户身份），SP 验签通过即建会话。攻击全部围绕"**断言内容与签名覆盖范围不一致**"做文章：

- **XSW 签名包装攻击（XML Signature Wrapping）**：XML 签名只对它引用的那个子树负责。攻击者把原始（已签名）断言挪到断言以外的新节点，在原位置插入篡改过 NameID/属性的伪造断言——SP 解析时读的是伪造断言，验签时却引用被挪走的原件，签名照样验过、身份已被偷换。USENIX '18 论文实测主流 SAML 库大量存在此类解析/验签脱节（与 JWT alg 混淆同病：**验证逻辑与实际消费的数据不是同一份**，对照 [EXP-JWT](../exp/EXP-JWT.md)）
- **SAML 注释注入**：把 NameID 构造成 `admin@corp.com<!--comment-->@evil.com`。不同解析器对注释处理不一致：SP 端忽略注释读出 `admin@corp.com`，IdP 端却按完整值记账为 evil.com 用户——同一个值两种读法，低权限账号借注释"变成"高权限
- **RelayState 投毒**：RelayState 本应在 SP 与 IdP 之间原样回传、只用于恢复上下文。若 SP 不校验回传值，攻击者注入的恶意 RelayState 会把认证完成的用户重定向到攻击者站点，常与开放重定向、OAuth code 截获链式利用
- 通用防御：验签必须绑定到**实际消费的那份断言**（签名 Reference URI 与解析节点一致）、禁用注释解析、RelayState 做白名单校验
- 实战工具：Burp 插件 **SAML Raider**（断言伪造/自签名证书/XSW 模板一键化）

## 凭证存储（防御侧必须知道）
- 口令绝不明文/可逆加密存储，用 bcrypt / scrypt / Argon2 + salt
- 哈希速度是"缺陷"也是"特性"：快哈希（MD5/SHA1）利于爆破，慢哈希提高成本
- 泄露后的连锁：口令复用 -> 撞库 -> 多平台失守

## MFA 与防爆破

### OTP 的常见缺陷
- **验证码不过期/可复用**：验证成功后不销毁，同一码可无限次重放；有效期过长（数分钟以上）等于给爆破留足窗口
- **无次数限制**：6 位 OTP 只有 10 万种组合，接口不限速、不限错误次数即可穷举——成功响应与失败响应的差异就是爆破的信号
- **重放**：用过的码还能再用；校验窗口过宽（同时接受前后 N 个 30s 时间片）进一步放大可爆破空间
- 正确姿势：一次性消费 + 严格时间窗口 + 错误次数限制与限速

### 防爆破机制及其反面
- **账户锁定**：N 次失败锁账户。反面一：知道用户名就能**恶意锁死他人**（锁定 DoS，攻击者可批量锁管理员）；反面二："账户已锁定"的差异化提示本身成了用户名枚举的区分点
- **指数退避**：失败越多等待越久（1s→2s→4s...），比硬锁定温和、不误伤真实用户，但可被并发请求与分布式爆破绕过
- **IP 信誉/风控**：按 IP 限速、拉黑高频源。反面：公司/校园网出口 IP 集中易误伤，攻击者换代理池即可绕过
- 完整方案 = 三者叠加 + 失败提示模糊化（统一返回"用户名或密码错误"）

### 图形验证码弱实现
- **前端校验**：答案随图片/JS 一起下发，浏览器里判完才提交——抓包直连接口即绕过
- **可预测**：验证码由时间戳/弱随机生成，可推算；或验证码 ID 与答案的映射关系可枚举
- **不过期/可复用**：同一验证码可无限次提交；验证通过后对应码不失效
- **OCR 秒杀**：无扭曲、无干扰线 = 等于没有验证码
- 正确姿势：服务端校验、一次性消费、短时效、强随机生成

## 攻击面速查映射
| 机制 | 典型攻击 | 利用篇 |
| --- | --- | --- |
| Cookie 自动携带 | CSRF | [EXP-CSRF](../exp/EXP-CSRF.md) |
| Cookie 可读 | XSS 窃取 | [EXP-XSS](../exp/EXP-XSS.md) |
| Session 可预测/固定 | 会话劫持 | 本篇 + [VUL-Crypto](./VUL-Crypto.md) |
| JWT 签名缺陷 | Token 伪造 | [EXP-JWT](../exp/EXP-JWT.md) |
| 只认证不授权 | 越权/IDOR | [EXP-IDOR](../exp/EXP-IDOR.md) |
| OAuth 回调 | 账号劫持 | 本篇 OAuth 节 |

## 参考
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [On Breaking SAML: Be Whoever You Want to Be (USENIX Security '18)](https://www.usenix.org/conference/usenixsecurity18/presentation/somorovsky)：SAML 生态 XSW 攻击的系统性研究
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
