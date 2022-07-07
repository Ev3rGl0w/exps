#coding:utf-8
import gmpy2
import libnum

c = 26412585555313909570657988150538399967717858405194991010369653793893864570102597595514
p = 6890036776605580403244370419138454499452919
q = 8671915061070896810677873479423356769368071
n = p*q
u = pow(c,(p+1)/4,p)
v = pow(c,(q+1)/4,q)
#   sp+tq=1  
s = gmpy2.invert(p,q)   # (p^-1) mod q 
t = gmpy2.invert(q,p)   # (q^-1) mod p
x = (t*q*u+s*p*v)%n
y = (t*q*u-s*p*v)%n

# print libnum.n2s(x%n)
# print libnum.n2s((-x)%n)
# print libnum.n2s(y%n)
# print libnum.n2s((-y)%n)

print (x%n)
print ((-x)%n)
print (y%n)
print ((-y)%n)