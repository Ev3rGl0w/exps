import gmpy2
import math


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

mod =[[2, 1], [3, 1], [5, 1], [7, 1], [11, 1], [13, 1], [17, 1], [19, 1], [29, 1], [31, 1], [37, 1], [41, 1], [47, 1], [53, 1], [61, 1], [73, 1], [97, 1], [101, 1], [103, 1], [107, 1], [113, 1], [137, 1], [139, 1], [151, 1], [167, 1], [173, 1], [179, 1]]
ans = []
leng = len(mod)
for i in range(leng):
	key = (p-1)/(pow(mod[i][0],mod[i][1]))
	gi = pow(g,key,p)
	hi = pow(w,key,p)
	for j in range(0,pow(mod[i][0],mod[i][1])):
		if pow(gi,j,p) == hi:
			ans.append(j)
			break

print ans

m = [i[0]**i[1] for i in mod]
print m
data = list(zip(ans, m))
x,n = CRT(data)
x = pow(x,1,p)
print str(x)