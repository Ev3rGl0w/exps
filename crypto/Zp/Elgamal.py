#coding:utf-8
from Crypto.Util.number import *
from gmpy2 import *

a = 201912723009
stander = a*(10**100) + 123456

big = 0
small = 0

tmp1 = stander
while True:
	if(isPrime(tmp1) and (tmp1-1)%2==0):
		q1 = (tmp1-1)/2
		if isPrime(q1):
			big = tmp1
			break
	tmp1+=1

tmp2 = stander
while True:
	if(isPrime(tmp2) and (tmp2-1)%2==0):
		q2 = (tmp2-1)/2
		if isPrime(q2):
			small = tmp2
			break
	tmp2 -= 1

flag = 0
if(abs(big - stander) > abs(stander - small)):
	p = small
	flag = 0
else:
	p = big
	flag = 1

q=(p-1)/2
print "big=>",big
print "small",small
print "p=>",p
print "q=>",q

# q = 1009563615045000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120233
# p = 2019127230090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000240467
gl=[]
for i in range(a,a+20000):
    if pow(i,2,p)!=1 and pow(i,q,p)!=1:
        gl.append(i)
        break

for i in range(a,a-20000,-1):
    if pow(i,2,p)!=1 and pow(i,q,p)!=1:
        gl.append(i)
        break
if abs(gl[0]-a)>=abs(gl[1]-a):
    g = gl[1]
else:
    g = gl[0]
print "原根g: "+str(g)

x = 20011218
y = pow(g,x,p)
print "公钥y: "+str(y)