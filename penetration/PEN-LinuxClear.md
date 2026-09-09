# Linux 痕迹清理

## 0x00 概述

主要记录 Linux 常见登录痕迹和命令历史相关文件的位置，以及手工清理或篡改的方法。适用于已经获得主机权限后，对登录记录和交互痕迹做最基础检查。

## 0x01 ssh登录日志

### 日志文件位置及命令
 | 命令	 | 日志文件	 | 功能 | 
 | ---- | ---- |---- |
 |w,who|/var/run/utmp|记录当前正在登录系统的用户信息，uptime记录系统启动时间|
 | last | 	/var/log/wtmp	 | 所有成功登录/登出的历史记录 | 
 | lastb | 	/var/log/btmp | 	登录失败尝试 | 
 | lastlog	 | /var/log/lastlog	 | 最近登录记录 | 

这些日志都是以二进制形式存储。   

### 清除方法
方案1，直接清空：  
```
# > /var/log/utmp
# > /var/log/wtmp
# > /var/log/btmp
# > /var/log/lastlog
```
方案2，使用脚本：

- [logtamper.py](./logtamper.py)
```
躲避管理员w查看(w)
python logtamper.py -m 1 -u root -i 192.168.0.188

清除指定ip的登录日志(lastb)
python logtamper.py -m 2 -u root -i 192.168.0.188

修改上次登录时间地点(lastlog)
python logtamper.py -m 3 -u root -i 192.168.0.188 -t tty1 -d 2014:05:28:10:11:12
```
### 不记录history
```
unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG
export HISTFILE=/dev/null
export HISTSIZE=0
export HISTFILESIZE=0
```

## 0x02 systemd journal 清理

### 1. 查看日志

```bash
# 查看 ssh 服务今天的日志
journalctl -u ssh --since today
# 按命令名 / 时间段过滤登录事件
journalctl _COMM=sshd --since "2024-01-01" --until "2024-01-02"
```

### 2. 清理方法

```bash
# 方案1：收缩归档，把 1 秒之前的日志全部回收（≈全清但保留 journal 结构）
journalctl --vacuum-time=1s
# 按体积收缩
journalctl --vacuum-size=1M

# 方案2：直接删除二进制日志文件
rm -rf /var/log/journal/*      # 持久化存储（journald.conf 中 Storage=persistent 时）
rm -rf /run/log/journal/*      # 易失性存储

# 删除后重启 journald，释放文件句柄、避免残留索引
systemctl restart systemd-journald
```

注意：journal 与 rsyslog 是两套链路，清 journal 不影响 `/var/log/syslog`、`/var/log/secure` 中的文本日志。

## 0x03 auditd 审计日志

auditd 日志位于 `/var/log/audit/audit.log`：

```bash
# 查看
grep -i execve /var/log/audit/audit.log
ausearch -m USER_LOGIN
```

清除：

```bash
> /var/log/audit/audit.log
# 或连同轮转文件一起
rm -f /var/log/audit/audit.log*
```

风险提示：auditd 由服务进程持有句柄，文件被删/清空的动作本身可能再触发新的审计记录；若配置了远程审计聚合或 SIEM 转发，本地清除无法掩盖，反而留下"日志缺失"特征。

## 0x04 history 精细清理

### 1. 定向删除单条记录

```bash
history                # 先看编号
history -d 1024        # 删除指定编号的命令
history -w             # 立即写回 ~/.bash_history
```

### 2. 注入假命令

```bash
# 删掉敏感命令后，补几条正常命令混淆时间线
history -d 1024
history -a
echo "ls -al /var/log/messages" >> ~/.bash_history
```

### 3. 彻底粉碎历史文件

```bash
# 多次随机覆写后删除，防止取证恢复
shred -zu /root/.bash_history
```

### 4. 退出时绕过 bash_history 写入

```bash
# 强杀自身 shell，bash 退出钩子（写 history）不会执行
kill -9 $$
```

## 0x05 时间戳伪造

### 1. touch 参考文件复制时间戳

```bash
# 让 /tmp/exploit 的 atime/mtime 与 /etc/passwd 完全一致
touch -r /etc/passwd /tmp/exploit
```

### 2. 三个时间戳说明

| 时间戳 | 含义 | 修改方式 |
| ---- | ---- | ---- |
| atime | 最后访问时间 | 读文件时更新，`touch -a` 单独修改 |
| mtime | 最后修改时间 | 文件内容变化时更新，`touch -m` 单独修改 |
| ctime | inode 变更时间 | 权限/属主/mtime 任何变化即更新，普通用户无法直接伪造 |

管理员常用 `find / -mtime -1`、`stat file` 排查近期改动；伪造 atime/mtime 可绕过这类粗筛，但 ctime 仍会暴露改动痕迹。

### 3. timestomp（meterpreter）

```
meterpreter > timestomp /tmp/exploit -z "01/01/2024 10:00:00"   # 修改 mtime
meterpreter > timestomp /tmp/exploit -r /etc/passwd              # 按参考文件复制时间戳
```

## 0x06 注意事项

- 不同发行版的日志路径、日志轮转和审计配置可能不同。
- 直接清空日志虽然简单，但特征很明显，容易被对比发现。
- 如果系统启用了 `auditd`、集中日志或堡垒机审计，本地处理并不能覆盖全部痕迹。

## Ref

- [logtamper.py 来源仓库](https://github.com/re4lity/logtamper)
- [清除入侵痕迹(win&Linux&web)](https://blog.csdn.net/yang2330648064/article/details/154017621)
- [MITRE ATT&CK T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070/)
