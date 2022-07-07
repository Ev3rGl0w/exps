#by 小梅梅梅
def CRT(Congruence_equations,n):
#x传入一个列表，keys代表着模数,items代表余数,n代表着所有模数的乘积
        def     gcd(a,b):     #求解最大公约数
                while a!=0:
                    a,b = b%a,a  
                return b
        
        def     findModReverse(a,m):#利用扩展欧几里得算法求模逆
                if gcd(a,m)!=1:
                    return None
                u1,u2,u3 = 1,0,a
                v1,v2,v3 = 0,1,m
                while v3!=0:
                    q = u3//v3
                    v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
                return u1%m
        
        M=n
        x=0
        for p in Congruence_equations.keys():
                x+=findModReverse(M//p,p)*Congruence_equations[p]*M/p  #CRT
        return int(x%M)    #返回同余方程组的解

def Pollig_Hellman(a,b,p,n_q_divide):#传入a,b,p,p-1的分解
        n=p-1
        c=len(n_q_divide)          #c代表唯一分解的素数的个数
        y=0   #y存alpha的值
        x={}  #x不断更新t和同余值,存放着不同q对应的离散对数的同余值
        for q in n_q_divide.keys():
                b_q=int(b)
                q_2=q**n_q_divide[q]  #q_2代表q的整除n的最大幂次
                for i in range(n_q_divide[q]):
                        if i==0:
                                for alpha in range(q):  #穷搜alpha
                                        if b_q**int(n//q)%p==a**int(n*alpha//q)%p:
                                               y=alpha
                                               x[q_2]=y
                                               break
                                else:
                                        print("出错了")
                        else:
                                t2=int((-1*y* q**(i-1))%n)
                                b_q=int((b_q*a**t2)%p)  #更新b的值
                                for alpha in range(p):
                                        if b_q**(n//int(q**(i+1)))%p==a**int(n*alpha//q)%p:
                                               y=alpha
                                               x[q_2] =y*q**i+x[q_2]
                                               break
                                else:
                                        print("出错了")
                        print(q,"(",i,")",":",y)
                print("q:",q_2,"x[",q_2,"]:",x[q_2])
        print(a,"^",CRT(x,n),"=",b)
        return CRT(x,n)               #利用中国剩余定理求解
mod = {2:1,3:1,5:1,7:1,11:1,13:1,17:1,19:1,29:1,31:1,37:1,41:1,47:1,53:1,61:1,73:1,97:1,101:1,103:1,107:1,113:1,137:1,139:1,151:1,167:1,173:1,179:1}
p = 26622572818608571599593915643850055101138771
g = 65537
w = 14632691854639937953996750549254161821338360

Pollig_Hellman(g,w,p,mod)
print("---\n")