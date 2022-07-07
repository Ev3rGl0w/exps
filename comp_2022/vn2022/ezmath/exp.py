from pwn import *
from hashlib import sha256

p = remote("node4.buuoj.cn",26612)
log_level='debug'

p.recvuntil("sha256(XXXX+")
last = p.recv(len("uHGW3pp6O0B4wdFD"))
p.recvuntil("== ")
ans = p.recv(len("3b038d87aa265ed58c236e15c97c582581fcb1d7b8bfb8eda695520f6134de47"))

p.recvuntil("[+] Plz Tell Me XXXX :")
# last = "bNdszXWokaZkQSFC"
# ans = "2b6b6b93f35e1917374899afe25ae460709d9e14a05e386082a1d8e7a9acb4eb"

str1 = '01234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM'

flagg = False
for a in str1:
	for b in str1:
		for c in str1:
			for d in str1:
				str2 = a+b+c+d+last
				sha = sha256(str2).hexdigest().encode()
				if sha == ans:
					print str2[:4]
					p.sendline(str2[:4])
					flagg = True
					break
			if flagg:
				break
		if flagg:
			break
	if flagg:
		break


for i in range(777):
	p.recvuntil("plz give me the ")
	num = int(p.recvuntil("th")[:-2],10)

	p.recvuntil("(the 1st 2^n-1 is 15):\n")
	p.sendline(str(num*4))
	print i

p.recvuntil("You get flag!")
p.interactive()
