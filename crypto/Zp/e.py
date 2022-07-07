#coding:utf-8
from functools import reduce
from Crypto.Util.number import *
import gmpy2



p =26622572818608571599593915643850055101138771
g =65537
w =14632691854639937953996750549254161821338360
N = [2,3,5,7,11,13,17,19,29,31,37,41,47,53,61,73,97,101,103,107,113,137,139,151,167,173,179]

def pp(N,g,w,p):
    #  x = a mod m
    a = []
    m = []
    for i in N:
        ai=pow(g,(p-1)//i,p)
        wi=pow(w,(p-1)//i,p)

        for j in range(i):
            if pow(ai,j,p)==pow(wi,1,p):
                m.append(j)
                a.append(i)
                break
    return a,m

def CRT(items):
    N = reduce(lambda x, y: x * y, (i[1] for i in items))
    result = 0
    for a, n in items:
        m = N // n
        d, r, s = gmpy2.gcdext(n, m)
        if d != 1: raise Exception("Input not pairwise co-prime")
        result += a * s * m
    
    return int(result % N), int(N)

p = 26622572818608571599593915643850055101138771
g = 65537
w = 14632691854639937953996750549254161821338360
N = [2,3,5,7,11,13,17,19,29,31,37,41,47,53,61,73,97,101,103,107,113,137,139,151,167,173,179]


m,a = pp(N,g,w,p)

print a
print m
data = list(zip(a, m))
x,n = CRT(data)
x = pow(x,1,p)
print("求解得X为: "+str(x))

#验证公私钥
