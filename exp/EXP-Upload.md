# 文件上传漏洞

## 一句话理解
文件上传漏洞的核心是应用把用户提供的文件当成“安全内容”保存、解析或执行，最终导致任意文件写入、脚本执行、配置覆盖或后续利用链成立。

## 常见危害
- 上传 WebShell，直接获取代码执行
- 上传脚本、配置文件或二次解析文件，间接实现执行
- 覆盖已有文件、篡改业务数据、破坏站点资源
- 上传恶意文档、图片、压缩包，触发后端解析漏洞
- 作为后续利用入口，联动文件包含、反序列化、XXE、图片处理漏洞

## 常见上传流程
典型链路如下：
1. 前端选择文件
2. 服务端校验扩展名、MIME、内容或尺寸
3. 文件落盘到某个目录
4. 应用返回访问路径
5. Web 服务器、应用服务器或后续组件对该文件进行解析

真正的风险往往不只在“能否上传”，而在：
- 上传后落到了哪里
- 文件最终以什么方式被访问
- 是否会被解释执行
- 是否会被二次处理

## 常见攻击面
- 头像上传、附件上传、工单附件
- 富文本编辑器、图片上传、从 URL 导入
- 模板导入、主题导入、插件安装
- Excel、CSV、PDF、DOCX、压缩包上传
- 后台导入导出、批量导入数据
- OSS / CDN / 对象存储直传

## 利用成立条件
文件上传漏洞通常至少满足以下一项：
- 可上传服务器会解析的脚本文件
- 可上传后缀可控、内容可控的危险文件
- 上传目录在 Web 可访问路径下
- 上传后的文件名、路径或后缀可预测
- 上传内容会被其他模块再次包含、反序列化或解析

## 常见校验点
### 1. 前端校验
例如限制后缀、限制 MIME、限制文件大小。

问题在于：
- 前端校验很容易被绕过
- 抓包可直接修改文件名、MIME、内容

### 2. 服务端校验
常见做法：
- 校验扩展名
- 校验 MIME
- 校验文件头
- 校验图片宽高
- 重命名并保存

问题在于单点校验经常不足，容易被组合绕过。

## 常见绕过思路
### 1. 扩展名绕过
常见方式：
- 双扩展名，如 `shell.php.jpg`
- 大小写混写，如 `shell.pHp`
- 特殊后缀，如 `phtml`、`php5`、`php7`
- Windows 环境中的点、空格、短文件名等解析差异

### 2. MIME 绕过
若服务端只看 `Content-Type`，可直接改包为：

```http
Content-Type: image/jpeg
```

但真实内容仍可为脚本或恶意数据。

### 3. 文件头绕过
如果系统只检查魔数，可在文件开头加图片头，再在后面拼接脚本内容。

### 4. 图片马
常见方式：
- 在图片末尾追加脚本
- 构造可通过 `getimagesize()` 等函数检查的图片
- 与 Apache / Nginx / IIS 配置缺陷或二次解析结合

### 5. 双写与黑名单绕过
若服务端只替换一次危险后缀，可能出现：
- `shell.pphphp`
- 双写关键字
- URL 编码或异常字符混淆

### 6. 路径与文件名控制
如果文件名、保存路径可控，还应关注：
- 路径穿越
- 覆盖已有文件
- 落到可执行目录
- 落到配置目录

## 常见利用方式
### 1. 直接上传脚本文件
最理想场景是目标直接允许上传：
- `php`
- `jsp`
- `asp`
- `aspx`
- `jspx`

### 2. 上传后缀伪装文件
例如上传为图片或文档，但后端或 Web 服务器会按脚本解析。

### 3. 配合二次解析
典型场景：
- Apache 某些配置按多扩展名解析
- IIS 存在历史解析问题
- Nginx / PHP-FPM 路由配置错误

### 4. 配合文件包含
即使上传目录不可直接执行，只要上传内容可控，也可能被：
- `include`
- `require`
- 模板引擎
- 其他解析器

### 5. 配合文档处理链
上传内容可能进入：
- 图片压缩
- OCR
- PDF 预览
- Office 转换
- 杀毒沙箱

此时漏洞可能从“上传漏洞”升级为“解析链漏洞”。

## 中间件与环境差异
### 1. PHP
重点关注：
- `php`、`phtml`、`php5`
- `.htaccess`
- 二次解析
- 包含链利用

### 2. Java
重点关注：
- `jsp`、`jspx`
- WAR 包、模板文件、类路径写入
- 组件自身上传逻辑

### 3. IIS / ASP
重点关注历史解析差异、NTFS 特性、后缀映射问题。

### 4. 对象存储
上传到 OSS / COS / S3 不一定能直接执行，但仍需关注：
- 文件内容是否对外可访问
- 是否会被前端直接渲染
- 是否会被下游服务再次处理

## .htaccess 完整利用
`.htaccess` 是 Apache 的目录级配置文件，只要满足以下前提，上传它就等于拿到了该目录内的“改配置权”：
- Web 服务器为 Apache，且 PHP 以 mod_php（模块）方式运行
- 主配置 `httpd.conf` 中对应目录设置了 `AllowOverride All`（虚拟主机/共享主机常见）
- 上传点允许写入 `.htaccess`（黑名单通常只拦脚本后缀，容易放过它）

三种主流写法：

```apache
# 写法一：让整个目录及子目录的 .jpg 都按 PHP 解析
AddType application/x-httpd-php .jpg

# 写法二：仅让匹配的文件按 PHP 解析，影响面最小（推荐）
<FilesMatch "shell.jpg">
SetHandler application/x-httpd-php
</FilesMatch>

# 写法三：PHP 模块指令，让目录下所有 PHP 文件执行前先包含 shell.jpg（PHP 5.x 常用）
php_value auto_prepend_file shell.jpg
```

利用流程：
1. 先上传写好的 `.htaccess`
2. 再上传内容为 PHP 代码、文件名为 `shell.jpg` 的文件
3. 访问 `shell.jpg`（写法三则访问目录内任意 `.php` 文件），代码执行

注意事项：
- `AddHandler php5-script .php5` 一类写法已过时（PHP 7 后 handler 名称变化），实战以上面三种为主
- `php_value` 只在 mod_php 下生效，php-fpm / fastcgi 环境下无效
- Nginx、IIS 不读取 `.htaccess`，该思路仅限 Apache

## 图片马制作与利用
图片马 = 正常图片头 + 脚本代码，用于骗过“只检查文件头 / 图片合法性”的校验。

制作命令：

```powershell
# Windows：/b 按二进制拼接图片，/a 按文本追加脚本
copy 1.jpg/b + shell.php/a shell.jpg
```

```bash
# Linux：直接拼接
cat 1.jpg shell.php > shell.jpg
```

一句话提醒：图片马本身永远不会被执行，单独访问图片只是显示或下载。它必须配合以下入口之一才成立：
- 文件包含漏洞：`include($_GET['file'])` → `?file=upload/shell.jpg`
- 解析漏洞：Nginx 畸形 URL、`1.jpg/.php`、Apache 多后缀、IIS 6.0 解析（见下节）
- 配置引导：`.htaccess` / `.user.ini` 把图片“变成”脚本

## 解析漏洞具体案例
### 1. Nginx CVE-2013-4547 畸形 URL 解析
- 影响版本：Nginx 0.8.41 ~ 1.5.6（官方修复于 1.4.4 / 1.5.7）
- 原理：URI 中出现未转义空格时，Nginx 解析请求行出错并截断，最终把 `shell.jpg` 当作 `.php` 脚本交给 fastcgi
- 畸形 URL：`shell.jpg\x20\x00.php`（空格 + 空字节 + `.php`）

报文示例（Burp Hex 视图下在空格 `20` 后插入 `00`）：

```http
GET /upload/shell.jpg .php HTTP/1.1
Host: target.com
```

十六进制实际为：

```
GET /upload/shell.jpg\x20\x00.php HTTP/1.1
```

上传图片马 `shell.jpg` 后，按畸形 URL 访问即可让其中 PHP 代码执行。

### 2. Nginx + php-fpm 路径解析（fastcgi_split_path_info）
- 利用形式：`/upload/1.jpg/.php`
- 原理：配置不当时（`cgi.fix_pathinfo=1`），PHP 找不到 `.php` 文件会向前回溯，最终把 `1.jpg` 当 PHP 执行。典型错误配置：

```nginx
location ~ \.php$ {
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    # 缺少 try_files 校验，直接把 URI 交给 php-fpm
}
```

- phpstudy 旧版集成环境（2014~2018）曾大面积默认存在，是 CTF 高频考点

### 3. Apache 多后缀解析
- 利用形式：`shell.php.xxx`
- 原理：Apache 识别文件类型时从右向左逐个匹配后缀，遇到不认识的 `.xxx` 继续向左，直到命中 `php`，最终按 PHP 解析
- 前提：`AddHandler` / `AddType` 类配置（mod_php 环境常见），并非所有 Apache 配置都成立

### 4. IIS 6.0 解析（经典历史漏洞）
- 分号截断：`x.asp;.jpg` —— IIS 6.0 忽略分号后内容，按 `x.asp` 解析
- 目录解析：`/x.asp/1.jpg` —— 目录名带 `.asp` 时，目录下所有文件按 ASP 解析
- 常配合 WebDAV 的 PUT / MOVE 方法直接写入或改名文件，形成组合利用

### 5. .user.ini 利用
- 前提：PHP 以 fastcgi / cgi 方式运行（nginx + php-fpm 常见），PHP >= 5.3
- 原理：`.user.ini` 是目录级 PHP 配置，目录下任意 PHP 文件执行前会先按 `auto_prepend_file` 包含指定文件

```ini
auto_prepend_file=shell.jpg
```

- 利用步骤：
  1. 上传 `.user.ini`（内容如上）到目标目录
  2. 上传含 PHP 代码的 `shell.jpg` 到同一目录
  3. 访问该目录下任意已存在的 `.php` 文件（如 `index.php`），`shell.jpg` 被自动包含执行
- 限制：目标目录必须存在可访问的 PHP 文件，否则没有触发点

## upload-labs 靶场指引
[upload-labs](https://github.com/c0ny1/upload-labs) 是最经典的文件上传靶场，共 20 关，覆盖黑盒绕过与白盒审计两条主线。

环境要求一句话：推荐 PHP 5.2.17 + Apache（module 模式）+ Windows，其中 Pass-19 需要 Linux 环境；缺少 php_gd2 / php_exif 组件会导致部分关卡无法复现。

| 关卡 | 考点（一句话） |
| --- | --- |
| Pass-01 | 前端 JS 校验——禁用 JS 或抓包直接改后缀 |
| Pass-02 | MIME 校验——抓包把 Content-Type 改成 image/jpeg |
| Pass-03 | 黑名单——php 被禁，换 phtml / php3 / php4 / php5 等可解析后缀 |
| Pass-04 | 黑名单全封——上传 .htaccess 让图片按 PHP 解析 |
| Pass-05 | 黑名单——大小写绕过（shell.pHp） |
| Pass-06 | 黑名单——Windows 文件名末尾空格（"shell.php "） |
| Pass-07 | 黑名单——Windows 文件名末尾点（"shell.php."） |
| Pass-08 | 黑名单——NTFS 数据流（"shell.php::$DATA"） |
| Pass-09 | 黑名单——点+空格+点组合（"shell.php. ."，deldot 只去一层） |
| Pass-10 | 黑名单——双写绕过（"shell.pphphp"，str_replace 只替换一次） |
| Pass-11 | 白名单——GET 型 %00 截断保存路径（PHP < 5.3.4） |
| Pass-12 | 白名单——POST 型 0x00 二进制截断保存路径（PHP < 5.3.4） |
| Pass-13 | 白名单——文件头检测，GIF89a 开头图片马 |
| Pass-14 | 白名单——getimagesize() 校验，图片马 |
| Pass-15 | 白名单——exif_imagetype() 校验，图片马 |
| Pass-16 | 白名单——二次渲染绕过（GIF 找保留区 / PNG 写 IDAT / JPG 难度最高） |
| Pass-17 | 白名单——条件竞争（上传后校验删除前的访问窗口） |
| Pass-18 | 白名单——条件竞争 + Apache 多后缀解析（shell.php.xxx） |
| Pass-19 | 白名单——move_uploaded_file 特性，save_path 可控用 "shell.php/." 截断（需 Linux） |
| Pass-20 | 白名单——数组验证绕过，save_name[] 数组传参使 end()/reset() 取值不一致 |

刷关建议：01~10 走黑名单/黑盒思路，11~20 走白名单/白盒审计思路；配合本文「.htaccess 完整利用」「图片马制作与利用」「解析漏洞具体案例」三节食用效果更佳。

## 实战排查思路
### 1. 先看上传后文件去向
重点确认：
- 落盘路径
- 返回 URL
- 是否在 Web 根目录下
- 是否允许直接访问

### 2. 再看后端校验逻辑
重点确认：
- 校验发生在前端还是服务端
- 校验的是扩展名、MIME、文件头还是内容
- 重命名策略是否安全

### 3. 最后看是否有二次利用链
例如：
- 上传后能否被包含
- 上传后能否被图像处理器再次解析
- 上传后文件名是否可预测

## 防御要点
### 1. 白名单校验
只允许业务必需的少量文件类型，不要依赖黑名单。

### 2. 服务端重新生成文件名
避免使用用户原始文件名和路径。

### 3. 上传目录与执行目录隔离
上传文件不要落在可执行目录，也不要与静态资源目录混放。

### 4. 验证真实内容
结合文件头、解析结果、实际解码能力做校验，而不是只看后缀和 MIME。

### 5. 关闭脚本解析
上传目录应明确禁止脚本执行。

### 6. 最小权限
上传目录仅授予写权限，不授予执行权限，应用也不应有任意覆盖系统文件的能力。

### 7. 二次处理安全
图片、文档、压缩包等上传后若要处理，需单独评估对应解析组件的风险。

## 速查清单
- 先看是否能上传任意文件，再看上传后是否可访问
- 先试扩展名绕过，再看 MIME、文件头、图片检查是否可绕过
- 检查上传目录是否在 Web 根下，是否能直接解析执行
- 检查是否存在路径穿越、文件覆盖、文件名预测
- 检查是否能联动文件包含、图片处理、文档解析、反序列化

## Reference
- [浅析文件上传漏洞](https://xz.aliyun.com/t/7365)
- [upload-labs 文件上传靶场（c0ny1）](https://github.com/c0ny1/upload-labs)
- [wonderkun/CTF 仓库](https://github.com/wonderkun/CTF)
- [Upload Attack Framework（CasperKid 经典上传攻击框架 paper）](https://github.com/UniSharp/laravel-filemanager/files/1107623/Upload_Attack_Framework.1.pdf)
