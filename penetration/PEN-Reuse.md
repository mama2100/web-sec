---
title: 端口复用
aliases: [端口复用, iptables, 流量复用]
category: penetration
status: current
updated: 2026-07
---

# 端口复用与转发

## 0x01 概述

端口复用适用于目标机器上某个高价值端口已经被业务占用，但你希望复用该端口对特定来源或特定流量做转发。常见场景：

- 只对你的来源 IP 复用 `80` / `443`。
- 把入口流量重定向到本地其他服务。
- 在不新增明显监听端口的情况下维持访问路径。

## 0x02 `iptables` 按来源地址复用

依照源地址区分，让来源为 `192.168.10.13` 访问 `80` 端口的流量转发到本地 `22` 端口：

```bash
iptables -t nat -A PREROUTING -p tcp -s 192.168.10.13 --dport 80 -j REDIRECT --to-port 22
```

查看规则是否生效：

```bash
iptables -t nat -nL
iptables -t nat -vnL PREROUTING
```

删除规则：

```bash
iptables -t nat -D PREROUTING -p tcp -s 192.168.10.13 --dport 80 -j REDIRECT --to-port 22
```

## 0x03 DNAT 转发到其他主机

如果要把入口端口转发到内网其他主机，而不是本机服务，可以使用 DNAT：

```bash
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.20:80
iptables -t nat -A POSTROUTING -p tcp -d 192.168.1.20 --dport 80 -j MASQUERADE
```

适合做跳转入口或临时暴露内网服务。

## 0x04 使用 `socat` 做本地复用

当系统不方便直接改防火墙时，也可以用用户态工具把流量转到其他端口：

```bash
socat TCP-LISTEN:8080,fork TCP:127.0.0.1:22
```

如果要对外暴露 TLS 前的明文服务，这种方式更直观，但痕迹也更明显。

## 0x05 检查点

- 目标内核是否开启了转发能力。
- 本机防火墙规则顺序是否会覆盖新规则。
- 业务端口是否已经绑定到 `127.0.0.1` 或特定网卡。
- 入口流量是否经过上层代理、CDN 或 WAF。

## 0x06 注意事项

- 端口复用的核心不是“隐藏”，而是“减少新增暴露面”。
- 涉及生产业务端口时，要先确认不会影响原有服务。
- 修改 NAT 规则后，记得同步检查回包路径。

## 0x07 `iptables` 按流量特征复用

除了按来源 IP（见 0x02），还可以用 string 模块按 payload 特征分流，实现“同一端口、按内容识别”：只有携带特定特征串的流量才被转发，其余正常业务流量不受影响：

```bash
# 将已监听端口流量复用：外部访问 80 端口特定特征流量转发到 22
# 实战中特征串通常用协议指纹，如 SSH 客户端首包的 "SSH-2.0" 或自定义暗号
iptables -t nat -A PREROUTING -p tcp --dport 80 -m string --string "xxx" --algo bm -j REDIRECT --to-port 22
# 常见玩法：SSLH（https/ssh 同端口复用，见下节）、按源 IP 白名单（同 0x02）
iptables -t nat -A PREROUTING -p tcp --dport 80 -s 攻击机IP -j REDIRECT --to-port 22
```

清理痕迹（用完即删，恢复业务原状）：

```bash
# 按规则编号删除：先 -L --line-numbers 找到编号，再 -D 指定行号
iptables -t nat -L PREROUTING --line-numbers -n
iptables -t nat -D PREROUTING 1
```

> 注意：`-m string` 只能匹配连接首个数据包的前几千字节，特征必须出现在首包 payload 中（SSH banner、HTTP 首行均满足）。

## 0x08 SSLH：同端口多协议复用

SSLH 的原理一句话：监听同一端口，读取客户端首包做协议探测（SSH banner / TLS ClientHello），识别出协议后再分流转发到对应后端端口，实现 https/ssh 同端口复用。

```bash
# 安装
apt install sslh
```

核心配置 `/etc/sslh.cfg`：监听 443，SSH 与 HTTPS（tls）分流到本机不同后端：

```text
listen:
(
    { host: "0.0.0.0"; port: "443"; }
);
protocols:
(
    { name: "ssh"; service: "ssh"; host: "127.0.0.1"; port: "22"; },
    { name: "tls"; host: "127.0.0.1"; port: "8443"; log_level: 1; }
);
```

```bash
# 改完配置重启服务
systemctl restart sslh
# 验证：443 端口同时可用 ssh 与 https 访问
ssh -p 443 user@1.1.1.1
curl -k https://1.1.1.1:443
```

相比 iptables string 匹配，SSLH 是完整代理进程、分流更可靠，但会新增一个常驻进程，痕迹相对明显。

## 0x09 Windows 端口复用（netsh portproxy）

Windows 上等价玩法是 netsh portproxy：复用已放行的 80 端口，把流量转到 3389（RDP），不新增任何对外监听：

```cmd
:: 将 80 端口流量转发到本机 3389，复用已放行的 Web 端口
netsh interface portproxy add v4tov4 listenport=80 connectaddress=127.0.0.1 connectport=3389
:: 查看已有转发规则
netsh interface portproxy show all
:: 删除规则（清痕）
netsh interface portproxy delete v4tov4 listenport=80
```

前置条件与注意：

- `listenport` 必须是 Windows 防火墙/安全组已放行且业务已在用的端口，否则流量根本到不了 portproxy。
- portproxy 依赖 IP Helper 服务（iphlpsvc），被禁用则规则不生效。
- 转发 3389 这类敏感端口前，先确认原 80 端口业务能接受 RDP 流量混入（正常 HTTP 请求不受影响，因为只有 RDP 客户端会去连）。

## 0x10 Web 端口复用（隐藏后门）

Web 层同理：Nginx stream 模块 `ssl_preread` 按 SNI 分流——读取 TLS ClientHello 的 SNI 字段，正常域名交给业务、恶意域名导流到后门端口，思路与端口复用一脉相承，落地细节见 [内网穿透工具](./PEN-Tunnel.md)。

## Ref

- https://book.hacktricks.wiki/en/generic-hacking/tunneling-and-port-forwarding.html
- https://www.wangan.com/articles/1050
- https://ipset.netfilter.org/iptables/manpages/iptables.html （iptables 官方文档）
- https://github.com/yrutschle/sslh （SSLH：协议探测同端口复用）