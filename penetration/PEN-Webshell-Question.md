# WebShell 命令执行异常排查

## 0x01 概述

WebShell 能连上但命令不执行，通常不是“没有权限”这么简单，更多是以下问题：

- 调用的解释器路径不对。
- Web 容器权限不足。
- 被安全策略、杀软或函数禁用拦截。
- 当前目录、编码或重定向方式有问题。

## 0x02 Windows 平台

### 1. 返回 `ret=1` 或执行失败

先切换命令解释器，排除当前调用程序不可用的问题。

```text
ret=-1> aslistcmd
C:/Windows/System32/cmd.exe            OK
C:/Windows/SysWOW64/cmd.exe            OK
C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe            OK
C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe            OK
C:/Windows/System32/WindowsPowerShell/v2.0/powershell.exe            FAIL
C:/Windows/SysWOW64/WindowsPowerShell/v2.0/powershell.exe            FAIL
ret=-1> ascmd C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
Will execute the command with C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe.
```

### 2. 常见原因

- `cmd.exe` 被替换或不可调用。
- PowerShell 版本存在兼容问题。
- Web 服务用户无执行权限。
- 杀软拦截了子进程创建。
- 输出被编码或重定向吃掉。

### 3. 快速检查项

先验证最短命令：

```cmd
whoami
ver
ipconfig
```

再验证重定向是否正常：

```cmd
whoami > C:\Windows\Temp\whoami.txt
```

如果命令能落文件，但 WebShell 无回显，问题通常在回显链路而不是命令执行本身。

### 4. 杀软拦截排查

命令"看起来执行了但结果不对"时，先按现象分型，再定位拦截发生在哪一层：

| 现象 | 更可能是 | 下一步 |
|---|---|---|
| HTTP 200，但无回显 | 子进程被杀软静默拦截，或输出被 WAF 内容审计过滤 | 重定向落文件再读；对命令做编码变形重试 |
| 命令偶尔成功、随后全部失效 | 子进程或落地文件被杀软查杀隔离（WebShell 直接 404 说明文件被删） | 确认 shell 文件是否还在；换免杀 shell 重传 |
| 连接直接重置（RST）、请求打不到应用 | WAF / 安全设备在传输层阻断（UA、路径、参数触发规则） | 换 UA 与请求头；分块 / 编码请求体 |

certutil 下载被拦的一句话思路：`certutil -urlcache -split -f` 早被杀软做成了专项规则，优先改走同功能系统组件（`bitsadmin`、`powershell`、`mshta`、`curl`、`ftp`），借"系统白名单进程"落地下载动作。

## 0x03 Linux 平台

### 1. 常见原因

- `sh` / `bash` 路径不一致。
- PHP 禁用了 `system`、`exec`、`shell_exec` 等函数。
- Web 服务用户无目录或命令执行权限。
- SELinux / AppArmor 限制。

### 2. 快速检查项

```bash
whoami
id
pwd
/bin/sh -c 'id'
```

如果 `system("id")` 失败，但 `echo` 正常，优先检查禁用函数和解释器路径。

## 0x04 排查顺序

1. 先确认命令解释器路径。
2. 再确认最短命令是否执行。
3. 再看是否有文件写入能力。
4. 最后再查安全策略和编码问题。

## 0x05 注意事项

- 命令执行问题和“没有回显”是两回事，要分开判断。
- Windows 下优先确认 `cmd.exe` 与 PowerShell 版本。
- Linux 下优先确认 `disable_functions`、SELinux、当前用户权限。

## 0x06 disable_functions 绕过（Linux 专项）

`system` 等命令函数返回空或报 `has been disabled`，先按 0x03 确认是 `disable_functions` 限制。完整原理与九种姿势（LD_PRELOAD、imap_open、ImageMagick、FFI、Windows COM、pcntl_exec、破壳漏洞、内核 UAF、适用条件速查表）见 [EXP-CI-PHP.md](../exp/EXP-CI-PHP.md) 的「disable_functions 绕过」章节，本节只记实战排查流程。

### 1. 实战排查三步

1. 拿环境信息：执行 `phpinfo()`（或蚁剑基本信息面板），记录 `disable_functions` 列表、PHP 版本、已加载扩展（openssl / imagick / ffi）、`sendmail_path` 是否存在。
2. 初筛方向：`mail` / `error_log` / `putenv` 未禁 → LD_PRELOAD；nginx + php-fpm 且 socket 可达 → PHP-FPM/FastCGI；PHP >= 7.4 且开启 ffi → FFI；Windows + PHP 5.x → COM 组件。
3. 能用蚁剑就用插件一键绕（下节），全部失败再回 EXP-CI-PHP.md 按速查表手工构造。

### 2. 蚁剑 disable_functions 插件（一键绕过）

- 安装：蚁剑「插件中心」搜索「绕过 disable_functions」安装（仓库见文末 Reference）。
- 用法：右键目标 Shell → 插件 → 绕过 disable_functions，按目标环境选模式，插件自动完成利用脚本上传、触发执行、生成代理 Shell 的全流程：

| 模式 | 原理一句话 | 关键条件 |
|---|---|---|
| LD_PRELOAD | 上传 so + `putenv` 挂载，`mail()`/`error_log()` 起子进程时加载执行 | Linux；mail / error_log 未禁，sendmail 可用（无 sendmail 时 so 用 `__attribute__((constructor))`，起子进程即触发） |
| Fastcgi / PHP-FPM | 直接向 fpm socket 发 FastCGI 请求，用 `PHP_VALUE` 起一个无限制的新 PHP Server | nginx + fpm 架构，unix/tcp socket 可达；IIS 管道模式不支持 |
| Apache mod_cgi | 写 `.htaccess` 把自定义后缀注册为 CGI 脚本，由 Apache 直接执行 | Apache + mod_cgi + `.htaccess` 可写 |
| UAF 系列 | 利用 PHP 内核 bug（JSON Serializer / GC / Backtrace 等）在用户态直接调用 `system` | 特定 PHP 版本区间（bug 号见插件文档） |
| PHP7.4 FFI | 通过 FFI 扩展直接声明并调用 C 的 `system` | PHP >= 7.4 且 ffi 开启 |
| iconv | `putenv` 设置 `GCONV_PATH`，`iconv()` 转换编码时加载恶意 gconv 模块 so | Linux，iconv 可用 |

- 通用收尾：多数模式（LD_PRELOAD、Fastcgi、iconv）的本质是"另起一个不受 disable_functions 限制的新 PHP WebServer，并在当前 Web 目录生成 `.antproxy.php` 做转发代理"，之后把蚁剑连接地址指到 `.antproxy.php`，虚拟终端即可正常执行命令。
- 提醒：`.antproxy.php` 是新落地的 WebShell 文件，用完记得删；该插件同样能绕 `open_basedir`。

### 3. 插件全失败时

- 回 [EXP-CI-PHP.md](../exp/EXP-CI-PHP.md) 速查表逐条试：`pcntl_exec`（pcntl 系未禁时）、破壳漏洞（CVE-2014-6271）、写入恶意 so 覆盖已加载扩展（需扩展目录可写）、`imap_open` 注入（CVE-2018-19518）等。
- 区分两类问题：函数被 php.ini 禁用（本节）与命令被杀软拦截（0x02 第 4 节）现象相似，处理方向完全不同——先确认 `disable_functions` 里确实有目标函数，再决定走哪条线。

## Reference

1. [Medicean/as_bypass_php_disable_functions - 蚁剑「绕过 disable_functions」插件](https://github.com/Medicean/as_bypass_php_disable_functions)
2. [AntSword-Labs/bypass_disable_functions - 插件配套测试环境](https://github.com/AntSwordProject/AntSword-Labs/tree/master/bypass_disable_functions/)
3. [EXP-CI-PHP.md - disable_functions 绕过原理与九种姿势、适用条件速查表](../exp/EXP-CI-PHP.md)
