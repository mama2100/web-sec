# Web 密码学误用（原理篇）

## 定位
本篇不讲密码算法本身的数学原理（那是 Crypto 方向的事），只讲 **Web 场景里把密码学用错的标准姿势**。每种误用都对应真实漏洞链，利用细节指向 exp/ 篇目。

## 编码 != 加密
- Base64、URL 编码、hex 只是编码，任何人可逆
- 常见幻觉："把数据 Base64 一下放 Cookie 就安全了"——攻击者解码改完再编码即可
- JWT payload 同理：看得懂，就看得到（见 [EXP-JWT](../exp/EXP-JWT.md)）

## 对称加密的误用
### 1. ECB 模式：分组重排
- ECB 每个明文块独立加密，相同明文块 -> 相同密文块
- 攻击者可以**切块重排**：把密文里"普通用户"块替换成另一个账号的"管理员"块
- 识别特征：密文长度是块整数倍，修改明文前缀观察密文重复段

### 2. CBC 比特翻转（Bit-flipping）
- CBC 解密时，篡改第 N 块密文的某字节，会可控地翻转第 N+1 块明文的对应字节
- 经典场景：Cookie 密文里 `role=0` 翻成 `role=1`（字节异或差值算好再改）
- 前提：知道部分明文结构，这在 Cookie/Token 场景几乎总是成立

### 3. CBC Padding Oracle
- 服务端对"填充是否正确"给出可区分响应（报错不同/时间不同）
- 攻击者逐字节解密任意密文，甚至加密任意明文
- 实战案例：**Shiro-721**（rememberMe 的 AES-CBC + 报错差异），工具见 README 4.2.2.2；**ASP.NET ViewState** 同理
- 工具：[padbuster](https://github.com/AonCyberLabs/PadBuster)

## 哈希的误用
### 1. 哈希长度扩展（Length Extension）
- MD5/SHA1/SHA256 等 Merkle-Damgard 结构哈希：知道 `H(secret + data)` 和 secret 长度，就能算出 `H(secret + data + padding + append)`
- 经典场景：签名设计为 `sign = md5(secret + params)`，攻击者不知道 secret 也能追加参数并伪造合法签名
- 工具：hashpump、[hash_extender](https://github.com/iagox86/hash_extender)
- 正确姿势：用 HMAC 而不是裸哈希拼接

### 2. 弱哈希存口令
- MD5/SHA1 无盐存口令 -> 彩虹表直接查
- 见 [VUL-Auth-Session](./VUL-Auth-Session.md) 凭证存储节

### 3. 加密当签名 / 签名当加密
- 只加密不验签 -> 可篡改（CBC 翻转、ECB 重排）
- 正确姿势：Encrypt-then-MAC，或直接用 AEAD（AES-GCM）

## 随机数误用
- **伪随机当安全随机**：`rand()`、`mt_rand()`、时间戳做种子 -> 可预测
- 高危场景：密码重置 token、Session ID、CSRF token、订单号
- 经典案例：PHP `mt_rand` 种子泄露后全序列预测；Java `java.util.Random` 同理
- 正确姿势：`/dev/urandom`、`random_bytes()`、`SecureRandom`、`secrets` 模块

## 密钥管理失误
- **硬编码密钥**：代码/配置文件里的密钥 -> 源码泄露即全线失守（Shiro-550 就是密钥硬编码在公开组件里）
- **默认密钥**：框架默认值不改（JWT `secret`、Django `SECRET_KEY` 示例值）
- **密钥复用**：加密和签名用同一把钥匙，一个环节泄露牵连全部

## 比较与时序
- 用 `==` 比较 token/签名 -> 逐字节短路比较泄露时序，理论可逐位爆破
- 防御侧用 `hash_equals()`、`hmac.compare_digest()` 恒定时间比较
- 实战意义有限（噪声大），但 CTF 偶见

## 其他常见误用

### 1. IV / Nonce 重用
- **CBC 固定 IV**：等价于"全局 ECB"——相同明文永远产生相同密文。攻击者虽解不了密，但能**辨识模式**（"这两条 Cookie 明文相同""这条密文和上次完全一样"），足以支撑重放与流量分析
- **CTR / GCM 重用 IV（致命级）**：密钥流由 `E(key, nonce)` 生成，nonce 重用即两条密文共享同一密钥流：`C1 xor C2 = P1 xor P2`——已知任意一段明文即可恢复另一段（crib-dragging 拖拽猜测）。GCM 下更糟：重用会泄露认证子密钥，攻击者可伪造任意密文的认证 Tag
- 高发姿势：IV 写死常量、全 0 IV、IV 递增可预测
- 正确姿势：CBC 每次用 CSPRNG 生成新 IV；CTR/GCM 的 nonce 必须保证同一密钥下绝不重复

### 2. RSA 误用三连
- **无填充（教科书 RSA）**：直接 `c = m^e mod n`。明文小到 `m^e < n` 时密文根本没取模，开 e 次方直接还原；同 n 同 e 的两段密文还可乘法结合出新明文的合法密文
- **低指数（e=3）**：一句话——**小指数广播攻击**：同一明文用 e=3 加密发给 3 个不同模数的接收者，三组密文经 CRT 合并得到 `m^3`，直接开立方还原明文
- **共模攻击**：一句话——同明文、同 n、不同 e1/e2（互素）的两份密文，扩展欧几里得求出 `a*e1 + b*e2 = 1`，则 `c1^a * c2^b = m mod n`，全程不需要私钥
- 正确姿势：加密必须 OAEP 填充，签名必须 PSS，e 用 65537

### 3. JWT alg 声明不可信
- 头部的 `alg` 字段由客户端控制：`alg: none` 伪造无签名 Token 绕过验签、RS256 改 HS256 拿公钥当 HMAC 密钥重签名（算法混淆）
- 本质：**服务端把算法选择权交给了攻击者**
- 利用手法与防御清单见 [EXP-JWT](../exp/EXP-JWT.md)

## 速查映射表
| 你看到的 | 应该怀疑 | 工具/方向 |
| --- | --- | --- |
| Cookie/参数是分组整数倍的密文 | ECB 重排、CBC 翻转、Padding Oracle | padbuster、手算异或 |
| 密文出现重复的相同块 | ECB 模式（块级模式泄露） | 切块重排（本篇 ECB 节） |
| 修改明文后密文前段不变 | ECB / CBC 固定 IV | 本篇 IV 重用节 |
| 报错区分"填充错误" | Padding Oracle | padbuster |
| `sign=md5(secret+data)` 形式的签名 | 长度扩展 | hashpump、hash_extender |
| token 可预测（时间戳/自增/序列重复） | 弱随机数 | 收集样本建模（本篇随机数节） |
| 源码用 `==` 比较 hash/签名 | 时序攻击 | 逐位爆破（本篇比较与时序节） |
| IV 写死/全 0/可预测递增 | IV 重用 | CBC 可辨识模式；CTR/GCM 直接丢密钥流（本篇 IV 重用节） |
| RSA e=3 / 无填充 / 多份密文同 n | 低指数广播、教科书 RSA、共模攻击 | CyberChef / sage，本篇 RSA 节 |
| JWT 头部 alg 可被客户端指定 | alg=none / RS256->HS256 混淆 | [EXP-JWT](../exp/EXP-JWT.md) |
| 源码/配置里躺着密钥 | 硬编码/默认密钥 | 源码泄露联动 [EXP-InfoLeak](../exp/EXP-InfoLeak.md)：拿到密钥即反打加密链（Shiro-550 路线） |

## 工具速查
- **CyberChef**：编码/解码/加解密全流程瑞士军刀——Base64/hex、AES 各模式（可指定 IV）、RSA、XOR，`Magic` 操作自动识别层层编码。网页版：https://gchq.github.io/CyberChef/
- **hashpump**（哈希长度扩展）一条命令：
  `hashpump -s <已知哈希> -d <已知数据> -k <secret长度> -a <追加数据>`
- **padbuster**（CBC Padding Oracle 解密/加密）一条命令：
  `padbuster <URL> <密文HEX> <块字节数> -cookies <会话Cookie> -encoding 16`
- **Burp Comparinator**（BApp Store 官方扩展，Comparer 的现代替代）：自动对齐 + 语法高亮的响应 diff，找 Padding Oracle 的可区分响应、定位 CBC 翻转影响范围的首选

## 参考
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Cryptopals Crypto Challenges](https://cryptopals.com/)：48 道实战题覆盖本篇 90% 的攻击原理，练完即有肌肉记忆
- [Crypto 101](https://www.crypto101.io/)：免费开源书，面向开发者讲密码学误用
- [CTF Wiki 密码学](https://ctf-wiki.org/crypto/)：中文 CTF 密码学知识体系
