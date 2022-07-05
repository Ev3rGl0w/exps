from pwn import *
from Crypto.Util.number import *
import gmpy2
import string
import hashlib
r = remote('101.201.144.230',44582)
table = string.digits + string.ascii_letters
context(log_level = 'debug')
def proof():
    r.recvuntil(b'sha256(XXXX')
    line = r.recvline()[:-1].decode()
    print(line)
    tmp = line[line.find('+ ') + 2:line.find(')')].strip()
    print(tmp)
    aim = line[line.find('== ') + 3:].strip()
    print(aim)
    for i in table:
        for j in table:
            for k in table:
                for l in table:
                    ans = i + j + k + l
                    if hashlib.sha256((ans + tmp).encode()).hexdigest() == aim:
                        print(ans)
                        r.recvuntil(b'Give me XXXX:')
                        r.sendline(ans.encode())
                        return
proof()
r.interactive()
