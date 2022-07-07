#coding:utf-8
from gmpy2 import *
from Crypto.Util.number import *
import math
#(a/b)
def jacobi(a,b):
	a = a%b
	if a == -1 or a==b-1:
		return pow(-1,(b-1)/2)
	elif a==2:
		return pow(-1,(b*b-1)/8)
	else:
		return pow(-1,(a-1)/2*(b-1)/2)*jacobi(b,a)

p=9628436377784788667
q=16394017319585898011
N=157848752737934733984337076039050641337
a = 201912723009
stand = a*(pow(10,18))

z = [p,q]
QR = []
small = stand - 50
big = stand + 50
for i in range(small,big):
	if i == stand:
		continue
	if gcd(i,N) == 1 and jacobi(i,p)==1 and jacobi(i,q)==1:
		QR.append(i)

ans = [abs(i-stand) for i in QR]
print "y=%ld"%QR[ans.index(min(ans))]
print "offset=%d"%min(ans)

y = QR[ans.index(min(ans))]
M = '10001101'
C = ''
for i in M:
	i = int(i)
	xi = pow(65537, i)
	if i == 1:
		c = (y * pow(xi, 2)) %  N
	else: 
		c = pow(xi, 2, N)
	C += str(c)
print 'C = %s' % C