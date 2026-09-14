---
title: 扫描与指纹识别
aliases: [端口扫描, 指纹识别, 目录爆破, nmap]
category: penetration
status: current
updated: 2026-07
---

# 扫描器专题

## 0x01 概述

扫描阶段的目标不是“把所有工具都跑一遍”，而是尽快回答三个问题：

1. 目标开放了哪些端口和服务。
2. 服务对应的协议、产品和版本是什么。
3. 哪些入口值得继续做漏洞验证和目录枚举。

## 0x02 常用流程

### 1. 主机发现

适合先确认存活主机，再决定后续扫描范围。

```bash
fping -asg 192.168.1.0/24
```

```bash
nmap -sn 192.168.1.0/24
```

### 2. 端口发现

#### `masscan`

优点是快，适合大网段粗扫。

```bash
masscan 192.168.1.0/24 -p1-65535 --rate 5000
```

#### `naabu`

适合快速发现开放端口，并和后续 Web 指纹工具配合。

```bash
naabu -host 192.168.1.10 -p top-1000
```

### 3. 服务识别

#### `nmap`

```bash
nmap -sV -sC -O -Pn 192.168.1.10
```

常用参数：

- `-sV`：服务版本识别。
- `-sC`：执行默认脚本。
- `-O`：系统识别。
- `-Pn`：跳过主机发现。

### 4. Web 资产识别

#### `httpx`

```bash
httpx -u http://192.168.1.10 -title -tech-detect -status-code
```

适合批量确认：

- 标题
- 状态码
- 中间件
- 是否存在跳转

### 5. 目录与接口枚举

#### `ffuf`

```bash
ffuf -u http://192.168.1.10/FUZZ -w wordlists.txt -mc all -fc 404
```

常见使用方式：

- 爆破目录：`/FUZZ`
- 爆破文件：`/admin/FUZZ.php`
- 爆破参数值：`/api?id=FUZZ`

### 6. 漏洞模板扫描

#### `nuclei`

```bash
nuclei -u http://192.168.1.10 -severity critical,high,medium
```

适合在确认指纹后做高效验证，但要注意：

- 模板版本是否最新。
- 请求特征是否容易触发 WAF。
- 不要对不稳定目标直接跑高危 POC。

## 0x03 Web 扫描建议

### 1. 先轻量识别，再做深度枚举

推荐顺序：

1. `httpx`
2. `nmap -sV`
3. `ffuf`
4. `nuclei`

### 2. 关注这些高价值信号

- 后台路径：`/admin`、`/manage`、`/console`
- 调试信息：报错页、目录列表、Swagger、Actuator
- 组件路径：`/jmx-console`、`/manager/html`
- 默认页面：路由器、NAS、监控系统、OA、CMS

## 0x04 内网扫描建议

- 优先控速，避免广播式高频扫描打爆交换机或告警设备。
- 先确定关键网段，再按业务优先级细扫。
- 对域环境先看 `445`、`135`、`139`、`88`、`389`、`3389`、`5985`。

示例：

```bash
nmap -Pn -p 445,135,139,88,389,3389,5985 192.168.10.0/24
```

## 0x05 常用命令速查

```bash
# Top 端口扫描
nmap --top-ports 1000 192.168.1.10

# 全端口 + 服务识别
nmap -p- -sV 192.168.1.10

# Web 标题和指纹
httpx -l urls.txt -title -tech-detect

# 目录爆破
ffuf -u http://target/FUZZ -w dict.txt -fc 404

# 模板扫描
nuclei -l urls.txt -severity high,critical
```

## 0x06 注意事项

- 扫描速度要和网络环境匹配，尤其是内网与公网弱带宽主机。
- 不要把漏洞验证和端口发现混在同一阶段，便于回溯问题。
- 对 Web 目标先做去重，避免对同一资产重复打点。

## 0x07 nmap 实战速查

### 1. 高频命令组合

```bash
nmap -sS -sV -O -p- 10.0.0.1          # 全端口+服务版本+系统
nmap -sU --top-ports 100 ip           # UDP top100
nmap --script vuln ip                 # 漏洞脚本批量
nmap -p 445 --script smb-vuln-ms17-010 ip   # 单漏洞验证
nmap -sn 10.0.0.0/24                  # 主机存活
nmap -v -A ip                         # 全面检测
```

### 2. NSE 脚本分类

| 分类 | 一句话说明 |
| --- | --- |
| `vuln` | 漏洞检测类脚本，直接探测目标是否存在已知 CVE 或配置缺陷 |
| `auth` | 认证绕过类脚本，检测匿名登录、空口令、默认凭证等认证弱点 |
| `brute` | 暴力破解类脚本，配合内置字典对 SMB/SSH/FTP 等服务爆破 |
| `discovery` | 信息收集类脚本，枚举共享目录、路由表、SNMP 团体名等资产信息 |

## 0x08 大网段与内网批量扫描

### 1. masscan 大网段

```bash
masscan -p80,443 10.0.0.0/16 --rate=10000
```

masscan 只判端口开闭、不做服务识别，标准打法是先粗筛再精扫：

```bash
# 先用 masscan 大网段粗筛，结果输出为 grepable 格式
masscan -p80,443 10.0.0.0/16 --rate=10000 -oG masscan.gnmap
# 提取开放端口的存活主机列表
awk '/\/open\//{print $2}' masscan.gnmap > hosts.txt
# 交 nmap 做服务版本精扫
nmap -sV -p80,443 -iL hosts.txt
```

### 2. 内网综合扫描器

```bash
# fscan：主机发现+端口扫描+弱口令爆破+常见漏洞检测（MS17-010、Redis 未授权等）一键全做
fscan -h 10.0.0.0/24

# kscan：以服务与 Web 指纹识别见长，先精准识别指纹再联动 POC 验证
kscan -t 10.0.0.0/24

# LadonGo：模块极多（爆破/漏扫/代理/内网穿透），适合大型内网横向批量扫描
LadonGo 10.0.0.0/24 OsScan
```

## 0x09 Web 专项

### 1. 目录扫描 dirsearch

```bash
# 目录/后台/敏感文件枚举，自带递归扫描与多扩展名字典
dirsearch -u https://target.com -e php,asp,jsp,html -t 30
```

### 2. 模板化漏扫 nuclei

```bash
# 只跑 CVE 类模板做定向验证
nuclei -u https://target.com -t cves/
```

nuclei 的价值在于模板化：命中即给出复现路径；自写 POC 也可以沉淀为自定义模板，与官方 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) Poc 仓库互为补充、持续更新。

### 3. 指纹识别 EHole / Wappalyzer

```bash
# EHole：红队常用指纹库，识别 CMS/框架/OA，指纹结论直接决定后续用哪套 POC
EHole finger -u https://target.com
```

Wappalyzer 是浏览器插件，打开页面即可看到技术栈，适合人工快速摸底。

## 0x10 反扫描与指纹对抗

一句话：控制扫描速率是绕过 IDS/IPS 告警的第一手段——`nmap --scan-delay 1s -T1` 限速慢扫、分时段分段扫，避免默认速率特征触发告警。

## Ref

- https://nmap.org/book/man.html
- https://nmap.org/book/nse.html
- https://github.com/projectdiscovery/naabu
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/ffuf/ffuf
- https://github.com/shadow1ng/fscan
