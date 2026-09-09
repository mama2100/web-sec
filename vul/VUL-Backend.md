# 错综复杂的后端逻辑及安全

## 0x00 前言
### web vs binary
Web安全不同于二进制安全，更多在于经验的积累和知识体系的广度，应为在上层应用架构中，让web看似入门简单，因为复杂的架构和技术栈，其实精通很有难度。而并非像二进制基础知识具有很好的通用性和拓展性。    
对比二进制安全研究人员来说，逆向是binary的核心，其实web手也是。通过黑盒的测试来检测漏洞，通过获取的信息来判断后端的架构。

>其实这篇有很多想说的内容，但又一言难尽，等以后有机会好好整理一下思路。         

## 0x01 分层（纵向）
业务服务主要在计算机网络的传输层（TCP、UDP），http应用服务是web安全的重要组成部分，但不是全部，各类的应用服务（数据库、远程桌面等）不能忽略。

![](../images/web-fc.png)
### 常见的应用服务

- 网站服务 (http[80],https[443]...)
- 远程控制 (ssh[22],telnet[23],rdp[3389]...)
- 数据库服务（mysql[3306],mssql[1433]...）
- 内存数据库服务 （redis[6379],memcache[11211]...）
- 文件管理服务(ftp[21],smb[193,445]...)
- 邮件服务（imap[143],pop3[110]...）
- 进程/设备间通信服务（RPC,MQTT(1883)...）

>Ps:不要忽略udp服务


### web应用分层
新增了容器和虚拟化      
#---用户侧---#
- 前端（html，JavaScript等）
- Web应用（CMS，OA，ERP等）
- MVC框架&组件（Thinkphp，FCKeditor等）
- 运行语言（PHP，.NET，Java Web等）
- Web中间件（Apache，Nginx，Tomcat等）
- 数据库系统（Mysql，Mssql等）
- 容器（Docker等）操作系统（Linux，Windows等）    
- 虚拟层（qemu，VM等）    
#---硬件侧---#


## 0x02 架构（横向）
通过[千万级并发下，淘宝服务端架构如何演进？](https://developer.51cto.com/art/201906/597895.htm)就可以知道，web应用的一个演化过程。对于用户侧呈现的web页面，其实背后可能是单个服务器支撑，也可能是复杂的架构系统。

本节主要站在攻击者角度来说，后端架构对于渗透测试的影响。

### 单机架构
对于攻击者而言，web服务和数据库系统都处于一台服务器中，结构简单。    
不同攻击面漏洞可以相互影响，例如：数据库写操作可以写入web执行路径中进而getshell。     
![](../images/web-arch-1.png)

### 站库分离
网站应用服务和数据库不在同一个服务器上。   
其实这是对于攻击者来说，一个架构阶段，作为开发者可能这是部署的方式而已。因为作为web入门漏洞SQL注入来说，是否是站库分离就很关键了。   
![](../images/web-arch-2.png)
### CDN
>CDN的全称是Content Delivery Network，即内容分发网络。其基本思路是尽可能避开互联网上有可能影响数据传输速度和稳定性的瓶颈和环节，使内容传输得更快、更稳定。通过在网络各处放置节点服务器所构成的在现有的互联网基础之上的一层智能虚拟网络，CDN系统能够实时地根据网络流量和各节点的连接、负载状况以及到用户的距离和响应时间等综合信息将用户的请求重新导向离用户最近的服务节点上。其目的是使用户可就近取得所需内容，解决 Internet网络拥挤的状况，提高用户访问网站的响应速度。

CDN主要用于网站动、静态资源的访问加速，也用于DDoS的安全防护。    
对于攻击者来说，就需要在众多CDN节点中找到真实的后端逻辑服务IP，进行攻击测试。
![](../images/web-arch-3.png)

#### 寻找真实IP（绕过CDN实操清单）
- **历史DNS记录**：域名接入CDN前的A记录会被历史解析库留存，用 [SecurityTrails](https://securitytrails.com/)、[微步在线](https://x.threatbook.com/)、[ViewDNS](https://viewdns.info/) 查历史解析，接入前的IP大概率就是源站。
- **子域名直连**：主站套了CDN，但 mail/dev/test/oa 等子域名往往直连源站，甚至与主站同C段，子域名收集（工具见 [PEN-Scanner](../penetration/PEN-Scanner.md)）后逐个反查。
- **SSRF/邮件头泄露**：找图片代理、Webhook 等能让服务器主动外连的功能（触发点见 [EXP-SSRF](../exp/EXP-SSRF.md)）；或触发注册/找回密码邮件，看邮件 `Received` 头中的源站IP。
- **SSL证书搜索**：在 [censys](https://search.censys.io/) / fofa 按证书 SAN 或 `https.title:"target.com"` 搜索，命中IP即挂着该域名证书的真实服务器。
- **MX记录**：邮件服务一般不套CDN，MX记录指向的邮件服务器常与源站同机房同C段，反查即可扩大战果。
- **网站备案/指纹定位**：国内站通过ICP备案信息定位主体与IP段；再配合 fofa `icon_hash`（favicon哈希）、特殊响应头、错误页特征全网定位真实IP。

### 负载均衡
>负载均衡建立在现有网络结构之上，它提供了一种廉价有效透明的方法扩展网络设备和服务器的带宽、增加吞吐量、加强网络数据处理能力、提高网络的灵活性和可用性。

![](../images/web-arch-4.png)

### 应用网关
随着应用逻辑的复杂度提成，需要统一入口管理，使得应用网关普遍使用。其承载了负载均衡，反向代理，API映射等诸多功能。   
对于攻击者来说，这就增加了新的攻击面和防护策略，可以攻击网关应用服务以及利用网关架构造成的前后端不一致的问题（请求走私），但同时网关各类防护策略也需要攻击进行绕过。

- **请求走私原理一句话**：HTTP/1.1 有 `Content-Length` 与 `Transfer-Encoding: chunked` 两种声明请求边界的方式，网关与后端对二者优先级理解不一致时请求边界错位，残留字节会拼到下一个用户的请求前，可越权、投毒缓存、劫持他人会话——详见 [EXP-Request-Smuggling](../exp/EXP-Request-Smuggling.md)。
- **WAF绕过思路一句话**：WAF与后端对同一请求的解析存在差异，分块传输（chunked把payload切碎，WAF不重组即漏检）与编码差异（多重URL编码/Unicode/大小写/注释，两端解码行为不一致）是最常用的两类绕过；本质上与请求走私同源——都是"多组件对同一数据理解不一致"。

### 以云平台承载系统
对于攻击者而言，系统复杂了，攻击面也细化成不同方向。      
![](https://s3.51cto.com/oss/201906/14/97b88fa7fb4f64aecd4701b12bef38b6.jpg-wh_600x-s_2360315611.jpg)

#### 云上攻击面
与传统IDC相比，云上架构的核心差异：边界从"网络边界"变成"凭证边界"，资产从"物理服务器"变成"账号下资源"——打下一台实例的收益，远不如拿到一枚凭证。具体攻击面：

- **SSRF打云元数据**：每台云实例都有元数据服务（AWS `169.254.169.254`、阿里云 `100.100.100.200`），Web应用一旦存在SSRF即可读取实例绑定的IAM/RAM角色临时凭证，从Web漏洞直接升级为云账号接管——触发点与手法见 [EXP-SSRF](../exp/EXP-SSRF.md)。
- **AKSK泄露**：AK/SK常硬编码在前端JS、小程序/APK反编译产物、公开仓库的 `.env`/`application.yml` 中，泄露后用官方CLI即可接管对应权限的全部云资源——凭证来源与利用流程见 [PEN-Cloud](../penetration/PEN-Cloud.md)。
- **对象存储接管**：Bucket权限配置错误（公共读写、可列举）可直接遍历/覆盖文件；拿到AKSK后更是连桶接管，覆盖静态资源即可批量挂马（存储型XSS/供应链投毒）。
- **容器/K8s暴露面**：Docker API（2375端口）未授权约等于宿主机root；K8s apiserver（6443/8080）匿名访问、etcd（2379）未授权可读全集群密钥——云原生架构下一层失陷即全链路沦陷。


## 0x03 分类（漏洞）

### Top 10
近些年漏洞的威胁分类也发生了很大变化，王道SQL注入也慢慢淡出历史的舞台，最新[owasp top 10](https://owasp.org/www-project-top-ten/)2021版，分类和排名都变化了很多。    
![](https://owasp.org/www-project-top-ten/assets/images/mapping.png)

#### 2021版变化要点解读
- **A01 Broken Access Control 登顶**（2017年第5升至第1）：越权类成为最大威胁来源——框架与预编译让注入类减少，但"接口在、校验不在"的越权只增不减，对应本仓库 [VUL-Logic](VUL-Logic.md) 的"身份与归属假设"与 [EXP-IDOR](../exp/EXP-IDOR.md)。
- **注入下滑至A03**：SQL注入从连续多年的榜首跌落，XSS也并入A03——反映ORM/参数化查询已成默认；但注入家族依然庞大（SQLi/SSTI/命令注入/XXE），对应 [EXP-SQLi-MySQL](../exp/EXP-SQLi-MySQL.md)、[EXP-SSTI-ALL](../exp/EXP-SSTI-ALL.md)、[EXP-XXE](../exp/EXP-XXE.md)。
- **新增A04 Insecure Design**：首次把"设计缺陷"独立成类——不是代码写错，而是设计假设本身可被违反，这正是业务逻辑漏洞的核心定义，对应 [VUL-Logic](VUL-Logic.md)。
- **新增A10 SSRF**：云时代服务端的外连能力本身成为攻击面，SSRF从"内网探测小漏洞"升格为云凭证泄露的主路径，对应 [EXP-SSRF](../exp/EXP-SSRF.md)。
- **A08 Software and Data Integrity Failures**：不安全反序列化并入此类（对象完整性假设被打破），对应 [EXP-Java-Unserialize](../exp/EXP-Java-Unserialize.md)。

#### OWASP 2021 → 本仓库文档映射
| OWASP 2021 | 主题 | 本仓库对应 |
| --- | --- | --- |
| A01 | 失效的访问控制 | [VUL-Logic](VUL-Logic.md)、[EXP-IDOR](../exp/EXP-IDOR.md) |
| A02 | 加密失败 | [VUL-Crypto](VUL-Crypto.md) |
| A03 | 注入 | [EXP-SQLi-MySQL](../exp/EXP-SQLi-MySQL.md)、[EXP-SSTI-ALL](../exp/EXP-SSTI-ALL.md)、[EXP-XSS](../exp/EXP-XSS.md)、[EXP-XXE](../exp/EXP-XXE.md) |
| A04 | 不安全设计 | [VUL-Logic](VUL-Logic.md) |
| A05 | 安全配置错误 | 本篇 0x02（架构/中间件配置问题） |
| A06 | 自带缺陷和过时的组件 | [EXP-Vul-Index](../exp/EXP-Vul-Index.md) |
| A07 | 身份识别和认证失败 | [VUL-Auth-Session](VUL-Auth-Session.md)、[EXP-JWT](../exp/EXP-JWT.md) |
| A08 | 软件和数据完整性失败 | [EXP-Java-Unserialize](../exp/EXP-Java-Unserialize.md) |
| A09 | 安全日志和监控失败 | 攻击侧对应：[PEN-WinClear](../penetration/PEN-WinClear.md)、[PEN-LinuxClear](../penetration/PEN-LinuxClear.md)（痕迹清理） |
| A10 | SSRF | [EXP-SSRF](../exp/EXP-SSRF.md) |

### 常见分类
注入类的漏洞，都是因为信任了输入参数，进而利用各类表达式语言进行利用。   

| 前/后端 | 类别     | 漏洞   | 目标     | 参考文档 |
| ------- | ---------- | -------- | ---------- | ---------- |
| 前端  | 跨域     | XSS      | 浏览器  | [EXP-XSS](../exp/EXP-XSS.md) |
|         |    跨域        | CSRF     | Request    | [EXP-CSRF](../exp/EXP-CSRF.md) |
|     后端    | 注入     | SSTI     | MVC        | [EXP-SSTI-ALL](../exp/EXP-SSTI-ALL.md) |
|      |    注入        | SQL注入 | 数据库  | [EXP-SQLi-MySQL](../exp/EXP-SQLi-MySQL.md) |
|         |    注入        | 命令注入 | 操作系统 | [EXP-CI-Java](../exp/EXP-CI-Java.md)、[EXP-CI-PHP](../exp/EXP-CI-PHP.md) |
|         | 不安全配置 | XXE      | XML        | [EXP-XXE](../exp/EXP-XXE.md) |
|         | 不安全设计 | 文件操作 | 文件系统 | [EXP-Upload](../exp/EXP-Upload.md)、[EXP-FileRead](../exp/EXP-FileRead.md) |
|         | 认证缺陷 | 请求走私 | Request    | [EXP-Request-Smuggling](../exp/EXP-Request-Smuggling.md) |
|         | 反序列化 | 反序列化 | 序列化对象 | [EXP-Java-Unserialize](../exp/EXP-Java-Unserialize.md)、[EXP-PHP-Unserialize](../exp/EXP-PHP-Unserialize.md) |
|         | SSRF       | SSRF     | Request    | [EXP-SSRF](../exp/EXP-SSRF.md) |



## 0x04 利用效果

1. 信息泄露
2. 业务功能（越权）
未授权、提升权限或横向越权来操作已有的功能
3. 业务干扰
影响已有的业务功能，eg:零元购
4. 文件操作（R/W）
5. 代码执行（Code）
6. 命令执行 (系统)

## 0x05 输入&输出
对于一个黑盒系统，最关键的就是输入与输出。   
Input->|blackbox|->Output    
对于白盒代码审计也是同等逻辑。   
Input->|function|->Output    


## Ref

- https://developer.51cto.com/art/201906/597895.htm
