import gmpy2


def cal(a,p,c,d):
    x0 = c[0]
    y0 = c[1]

    x1 = d[0]
    y1 = d[1]

    if(x0 == x1 and y0 == y1):
        l = ((3*x1**2 + a)*gmpy2.invert(2*y1,p)) % p
        re_x = (l**2 - 2*x1) % p
        re_y = (l*(x1 - re_x) - y1) % p
        return (int(re_x),int(re_y))
    else:
        l = ((y1-y0)*gmpy2.invert(x1-x0,p)) % p
        re_x = (l**2 - x0 - x1) % p
        re_y = (l*(x1 - re_x) - y1) % p
        return (int(re_x),int(re_y))

a = 1
b = 1
p = 23

P = (3,10)
Q = (9,7)
G = (17,20)
M = cal(a,p,P,Q)
print cal(a,p,M,G)