import random
import math


num = 201912723009
def fermat_test(n, rounds):
    for i in range(rounds):
        b = random.randint(2,n-2)#生成一个[2,n-2]之间的随机整数
        gcd = math.gcd(b,n)  #gcd = (b,n)
        if gcd > 1:
            return 0
        r = pow(b,n-1,n)#r = b^n-1 mod n
        if r != 1:
            return 0
    return 1

target = 0

while target != 1:
    n = random.randint(num*pow(10,50),(num+1)*pow(10,50))
    target = fermat_test(n,100)

print(n)