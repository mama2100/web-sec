# Windows 痕迹清理

## 0x01 概述
Linux 侧清理见 [PEN-LinuxClear](./PEN-LinuxClear.md)，本篇覆盖 Windows：事件日志、RDP 痕迹、文件执行痕迹、工具残留。核心认知：**清理动作本身会产生新日志**，EDR 时代清日志更多是"减少证据"而非"无影无踪"。

## 0x02 前置条件
- 管理员/SYSTEM 权限（清安全日志需要 SeSecurityPrivilege）
- 了解目标环境是否有 EDR/Sysmon/日志集中转发（有转发的话本地清了也没用）

## 0x03 事件日志
### 1. 关键日志与事件 ID
| 日志 | 关注点 |
| --- | --- |
| Security | 4624 登录成功、4625 登录失败、4634 注销、4720/4726 账号增删、4732 加组、7045 服务安装 |
| System | 服务安装、驱动加载 |
| PowerShell/Operational | 4103/4104 脚本块日志（最危险，命令全记录） |
| Sysmon | 进程创建(1)、网络连接(3)、文件创建(11) |

### 2. 清理命令

```powershell
# 查看日志列表
wevtutil el

# 清空指定日志（会产生 1102"日志已清除"事件）
wevtutil cl Security
wevtutil cl System
wevtutil cl Application

# PowerShell 方式
Clear-EventLog -LogName Security
```

### 3. 更精细的做法
- **不整清，单条删**：Windows 不支持原生单条删除，需用工具（如 EventCleaner、Invoke-Phant0m 停日志线程）
- **暂停记录**：`Invoke-Phant0m` 找到并挂起 EventLog 服务线程，之后的操作不落地——比"清"更干净
- 注意 1102/104 事件本身就是强告警信号，清完日志最好伪造/覆盖时间线

工具链接：

- EventCleaner（单条删除 + 暂停日志线程）：https://github.com/QAX-A-Team/EventCleaner
  - 单条删除：`EventCleaner.exe clean 16`（删除指定记录号；配套 `suspender` 暂停日志线程、`normal` 恢复）
- Invoke-Phant0m（杀 EventLog 服务线程）：https://github.com/hlldz/Invoke-Phant0m
  - 用法：`powershell -exec bypass -c "Import-Module .\Invoke-Phant0m.ps1; Invoke-Phant0m"`

## 0x04 RDP 与远程登录痕迹
```powershell
# RDP 连接记录（按用户）
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
reg delete "HKCU\Software\Microsoft\Terminal Server Client\Servers" /f

# 默认记录
reg delete "HKCU\Software\Microsoft\Terminal Server Client\Default" /f
```

- 登录事件在 Security 4624（LogonType 10 = RDP）
- 蓝队取证还会看 `C:\Users\<user>\AppData\Local\Microsoft\Terminal Server Client\Cache\`（画面缓存，删不掉操作痕迹就清理用户目录）

## 0x05 文件与执行痕迹
| 痕迹点 | 位置 | 说明 |
| --- | --- | --- |
| Prefetch | `C:\Windows\Prefetch\*.pf` | 程序执行证据，删除对应 `.pf` |
| ShimCache | 注册表 SYSTEM | 重启才写盘，热机器上改注册表意义有限 |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | 首次执行记录 |
| Recent/快捷方式 | `%APPDATA%\Microsoft\Windows\Recent` | 最近打开文件 |
| JumpLists | `Recent\AutomaticDestinations` | 任务栏跳转记录 |
| 临时目录 | `%TEMP%`、`C:\Windows\Temp` | 工具落地清理 |

时间戳伪造（MSF 自带）：

```text
meterpreter > timestomp C:\tools\nc.exe -f C:\Windows\System32\kernel32.dll
```

### USN Journal（NTFS 变更日志）

取证原理一句话：USN Journal 是 NTFS 卷级变更日志，持续记录文件的创建/删除/重命名/写入，**文件删了日志还在**，蓝队用它还原已删文件名与时间线。

```powershell
# 查询 C 盘 USN Journal 状态
fsutil usn queryjournal c:

# 读取具体记录（Win10 1607+）
fsutil usn readjournal c:

# 删除 C 盘 USN Journal（/D 等待删除完成）
fsutil usn deletejournal /D c:
```

### DNS 缓存与执行痕迹

```powershell
# 查看本机 DNS 缓存——暴露最近解析过的域名（C2、下载源、内网主机名）
ipconfig /displaydns

# 清除 DNS 缓存（cmd 等价：ipconfig /flushdns）
Clear-DnsClientCache
```

- DrWatson / WER 崩溃转储：进程崩溃时 Windows Error Reporting 会在 `%LOCALAPPDATA%\CrashDumps` 落 `.dmp` 文件，包含崩溃瞬间的进程内存（工具路径、配置、密钥都可能在内），落地工具崩溃后记得检查这里。

## 0x06 其他痕迹点
- 计划任务：`schtasks /query`，删自建的
- 服务：`sc query`，删自建的（7045 事件记得处理）
- 新增账户：`net user`，删后处理 4720/4726
- PowerShell 历史：`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- 回收站、浏览器历史（蓝队常看）

## 0x07 注意事项
- 有 Sysmon/EDR 的环境，清理动作（wevtutil、reg delete）本身就是检测点，优先考虑"从一开始就少产生"（内存执行、无文件落地）
- 日志转发到 SIEM 后本地清理无效，评估环境再决定投入
- 全清日志在蓝队眼里等于"这里被打了"，精细清理优于暴力清空

## 0x08 参考
- [Windows 取证分析常用痕迹点](https://github.com/uknowsec/Active-Directory-Pentest-Notes)
- [EventCleaner - 事件日志单条删除/线程挂起](https://github.com/QAX-A-Team/EventCleaner)
- [Invoke-Phant0m - 终止 EventLog 服务线程](https://github.com/hlldz/Invoke-Phant0m)
