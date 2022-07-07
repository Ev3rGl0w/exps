# -*- coding: utf-8 -*-
# def gcd(a,b):
#     r=a%b
#     while(r!=0):
#         a=b
#         b=r
#         r=a%b
#     return b

# def euler(a):
#     count=0
#     for i in range(1,a):
#         if gcd(a,i)==1:
#             count+=1
#     return count

# def order(a,n,b):
#     p=1
#     while(p<=n and (b**p%a!=1)):
#           p+=1
#     if p<=n:
#           return p
#     else:
#           return -1

# def primitive_root(a):
#     n=euler(a)
#     prim=[]
#     for b in range(2,a):
#         if order(a,n,b)==n:
#             print b


# print primitive_root(65537)

p=65537
g=3

if(pow(g,p-1,p**2)==1):
    print g+p
else:
    print g