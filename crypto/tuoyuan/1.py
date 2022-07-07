#coding:utf-8
from Crypto.Util.number import*
import gmpy2

#求G1+G2
def cal(G1,G2):
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73
    a=0
    b=7
    if G1 != G2:
        y = ((G2[1] - G1[1])*gmpy2.invert(G2[0] - G1[0],p))%p
        x3 = (y*y-G1[0]-G2[0])%p
        y3 = (y*(G1[0] - x3) - G1[1])%p
        return [int(x3),int(y3)]
    y = ((3*G1[0]*G1[0]+a)*gmpy2.invert(2*G1[1],p))%p
    x3 = (y*y-G1[0]-G2[0])%p
    y3 = (y*(G1[0] - x3) - G1[1])%p
    return [int(x3),int(y3)]


#递归法求解kG
def solve(k,G):
    if k == 1:
        return G
    if k == 2:
        return cal(G,G)
    if k%2 == 0:
        tG = solve(k//2,G)
        return cal(tG,tG)
    tG = solve(k//2,G)
    return cal(cal(tG,tG),G)


#求椭圆曲线y
def caly(a,p):
    if pow(a,(p-1)//2,p) == p-1:
        return False
    if p%4 == 3:
        return pow(a,(p+1)//4,p)
    if p%8 == 5:
        if pow(a,(p-1)//4,p) == 1:
            return pow(a,(p+3)//8,p)
        else:
            while True:
                b = 3
                if pow(b,(p-1)//2,p) == p-1:
                    break
            return (pow(b,(p-1)//4,p)*pow(a,(p+3)//8,p))%p
        
        
        
x0=0x3B4C382CE37AA192A4019E763036F4F5DD4D7EBB
y0=0x938cf935318fdced6bc28286531733c3f03c4fee
p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73
G = [x0,y0]


xue=201912723009

Pu = solve(xue,G)
print "公钥为"+hex(Pu[0]) + ","+hex(Pu[1])


k  = 201912723009
m  = bytes_to_long("Hello world")#明文
kG = solve(k,G)#kG

m*=30
while True:
    if pow(m*m*m+7,(p-1)//2,p) == 1:
        break
    m+=1
Pm = [m,caly(m*m*m+7,p)]
Cm = cal(Pm,solve(k,Pu))
print "kG = "+ str(kG)
print "cG = "+ str(Cm)

xuekG = solve(xue,kG)
mG = cal(Cm,[xuekG[0],-xuekG[1]])
print(long_to_bytes(m//30))