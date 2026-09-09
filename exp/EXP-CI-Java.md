# 命令注入&代码执行-Java

## 一句话理解
Java 场景下的命令执行，不一定都表现为“传统 shell 注入”，很多时候是开发直接调用 `Runtime`、`ProcessBuilder`、脚本引擎或表达式引擎，导致用户输入能够触发系统命令、脚本执行或代码执行。

## 常见危险类与接口

```text
java.lang.Runtime
java.lang.ProcessBuilder
java.lang.ProcessImpl
javax.script.ScriptEngineManager
groovy.lang.GroovyShell
```

## 常见危害
- 执行系统命令
- 文件读写
- 下载并执行恶意程序
- 反弹 Shell
- 结合表达式注入、反序列化、模板注入达成 RCE

## 实战理解
Java 命令执行常见分成两类：
1. 直接命令执行：开发显式调用系统命令
2. 间接代码执行：用户输入进入脚本引擎、表达式引擎、Groovy 等动态执行组件

## 典型危险点
### 1. `java.lang.Runtime`

```java
Runtime.getRuntime().exec(cmd)
```

重点：
- `exec()` 默认不是把整串命令交给 `/bin/sh -c` 或 `cmd /c`
- 因此很多场景并非经典“分隔符命令注入”，而更偏向“参数注入”
- 如果开发手动套了 shell，例如 `"/bin/sh", "-c", cmd"`，才更接近传统命令拼接注入

参考：
- [GTFOBins](https://gtfobins.github.io/)

### 2. `java.lang.ProcessBuilder`

```java
StringBuilder sb = new StringBuilder();

try {
    String[] arrCmd = {cmd};
    ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
    Process p = processBuilder.start();
    BufferedInputStream in = new BufferedInputStream(p.getInputStream());
    BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
    String tmpStr;

    while ((tmpStr = inBr.readLine()) != null) {
        sb.append(tmpStr);
    }
} catch (Exception e) {
    return e.toString();
}

return sb.toString();
```

重点关注：
- 参数数组是如何构造的
- 是否把用户输入直接作为完整命令
- 是否显式调用 shell

### 3. `java.lang.ProcessImpl`

```java
Class clazz = Class.forName("java.lang.ProcessImpl");
Method start = clazz.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
start.setAccessible(true);
start.invoke(null, new String[]{"calc"}, null, null, null, false);
```

这类写法常见于反射调用或绕过某些表层审计规则的场景。

### 4. `javax.script.ScriptEngineManager`

```java
/*jsurl
var a = mainOutput();
function mainOutput() {
  var x = java.lang.Runtime.getRuntime().exec("calc");
}
*/
ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
String cmd = String.format("load(\"%s\")", jsurl);
engine.eval(cmd, bindings);
```

重点：
- 动态脚本执行本身就极其危险
- 若支持远程加载脚本，风险更高
- 需关注 JDK 版本、脚本引擎实现和禁用情况

### 5. `groovy.lang.GroovyShell`

```java
public void groovyshell(String content) {
    GroovyShell groovyShell = new GroovyShell();
    groovyShell.evaluate(content);
}
```

Groovy 一旦接收用户可控表达式，通常很容易演变为高危代码执行。

## 常见利用场景
- 后台执行诊断命令
- 插件系统、脚本系统、规则引擎
- 表达式求值功能
- 调试接口
- 任务调度、运维平台、CI/CD 平台
- 动态模板或 Groovy 扩展点

## 常见排查思路
### 1. 先找危险 API
代码审计重点搜：
- `Runtime.getRuntime().exec`
- `new ProcessBuilder`
- `ScriptEngineManager`
- `GroovyShell`
- 反射调用命令执行类

### 2. 再看输入如何进入
重点确认：
- 是作为完整命令
- 还是作为参数
- 还是进入脚本/表达式字符串

### 3. 判断是否经过 shell
这会直接影响利用方式：
- 若经过 shell，优先尝试经典命令注入思路
- 若未经过 shell，更多考虑参数注入和程序行为利用

### 4. 看是否有回显
区分：
- 直接回显标准输出
- 报错回显
- 无回显但可出网

## 常见绕过思路
### 1. 参数注入
Java 里很多所谓“命令注入”本质是向系统命令追加危险参数，而不是简单拼 `;`。

### 2. 平台差异
Windows 和 Linux 在：
- shell 语法
- 路径
- 可执行程序
- 参数格式

上都不同，payload 不能混用。

### 3. 间接执行链
即使找不到 `Runtime.exec()`，也要继续看：
- 脚本引擎
- Groovy
- 表达式引擎
- 反序列化链

## 回显技巧

命令执行点往往没有回显：`Runtime.exec()` 默认不返回输出，输出留在管道里没人读。按目标环境选回显方式。

### 1. 写文件回显（最通用）

让命令把输出重定向到 Web 根目录下的静态文件，再走 HTTP 读回：

```java
// Windows：确认 webroot 可写后，把输出落到可被静态资源映射的路径
String[] cmd = {"cmd", "/c", "whoami > ..\\webapps\\ROOT\\1.txt"};
new ProcessBuilder(cmd).start();
```

```java
// Linux：注意重定向是 shell 语法，必须经 /bin/sh -c，exec(String) 直传不生效
String[] cmd = {"/bin/sh", "-c", "id > /var/www/html/1.txt"};
new ProcessBuilder(cmd).start();
```

随后请求 `http://target/1.txt` 即可读回命令输出。关键点：确认 Web 根目录路径（报错泄露 / actuator / 已知框架默认路径）且该目录可写、文件落在静态资源可访问的位置。

### 2. 异常回显

把命令输出塞进异常 message，借全局异常处理器或 debug 报错页回显到 HTTP 响应：

```java
// 读一次进程输出，包装成异常抛出，报错页会把 message 原样吐出来
Process p = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "whoami"});
byte[] buf = new byte[1024];
int len = p.getInputStream().read(buf);
throw new Exception(new String(buf, 0, len));   // 异常信息即命令输出
```

前提：应用处于 debug/开发模式，异常 message 没有被统一错误页吞掉。

### 3. 内存马一句话思路

有代码执行能力但落地 webshell 文件会被查杀 / 目录不可写时，改注册 Tomcat Filter 型内存马：动态创建 Filter 并注册到 `ServletContext`（反射调用 `ApplicationContext#addFilter` 突破访问限制），Filter 内拦截指定 URL 参数并执行命令——无文件落盘、特征小，缺点是重启即失效。

注入代码与各容器（Tomcat/Resin/WebLogic）差异详见 [Webshell-Bypass](../penetration/Webshell-Bypass.md)。

## 防御要点
### 1. 避免直接调用系统命令
优先使用 Java 原生 API 处理文件、网络、压缩等操作。

### 2. 使用固定参数模板
如必须调用外部程序，命令和参数都应做严格白名单，不允许用户传完整命令行。

### 3. 禁止动态脚本执行
不要把用户输入传给 `ScriptEngine`、`GroovyShell` 或类似接口。

### 4. 最小权限
运行 Java 服务的账户不应具备高权限和敏感目录写权限。

## 完整审计对照

同一段业务（ping 诊断接口），漏洞版与修复版对照。

### 漏洞版（Controller 接收 ip -> 拼接 -> Runtime.exec）

```java
@RestController
public class PingController {

    @GetMapping("/ping")
    public String ping(@RequestParam("ip") String ip) {
        // 漏洞：用户输入直接拼接进 shell 命令，且显式调用了 /bin/sh -c
        String cmd = "ping -c 4 " + ip;
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();   // 还把输出原样回显，攻击者可直接看结果
        } catch (Exception e) {
            return e.toString();
        }
    }
}
```

利用报文（分号拼接即注入）：

```http
GET /ping?ip=127.0.0.1;whoami HTTP/1.1
Host: target.com
```

### 修复版（白名单校验 + 参数化调用）

```java
@RestController
public class PingController {

    // 白名单：只放行 IPv4/IPv6 合法字符，其余输入直接拒绝
    private static final Pattern IP_PATTERN =
            Pattern.compile("^[0-9a-fA-F.:]{1,45}$");

    @GetMapping("/ping")
    public String ping(@RequestParam("ip") String ip) {
        // ① 白名单校验：不符合 IP 格式直接拒绝，杜绝任何特殊字符进入命令
        if (!IP_PATTERN.matcher(ip).matches()) {
            return "invalid ip";
        }
        try {
            // ② 参数化调用：不经 shell，命令与参数全部固化，ip 只能作为最后一个参数
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", ip);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            // ③ 超时控制：防止进程挂死拖垮服务
            if (!p.waitFor(5, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return "timeout";
            }
            String out = new String(p.getInputStream().readAllBytes());
            // ④ 回显最小化：只返回前 1KB，避免输出内容被二次利用
            return out.substring(0, Math.min(out.length(), 1024));
        } catch (Exception e) {
            return "error";   // 不回显异常细节
        }
    }
}
```

修复三要素：**白名单校验输入 → 不经 shell 的参数化调用 → 最小信息回显**，缺一不可。只做黑名单过滤（删空格、删分号）仍可被 `$IFS`、编码、换行等手法绕过。

## 速查清单
- 先搜 `Runtime`、`ProcessBuilder`、`ScriptEngineManager`、`GroovyShell`
- 先分清命令执行、参数注入还是脚本执行
- 判断是否经过 shell，再选择利用思路
- 检查是否存在标准输出回显、错误回显或外带能力
- 继续联动表达式注入、模板注入和反序列化链

## Reference
- [Java 代码审计之 RCE（远程命令执行）](https://blog.51cto.com/u_13963323/5066457)
- [GTFOBins](https://gtfobins.github.io/) —— Java 参数注入场景下可被滥用的系统命令速查
- [Oracle - Secure Coding Guidelines for Java SE](https://www.oracle.com/java/technologies/javase/seccodeguide.html) —— Java 安全编码规范
