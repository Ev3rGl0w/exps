p = 65537
a = 17
b = 17**3

def jie(n):
    for i in range(1,p):
        if(pow(a,i,p)==1):
            return(i)

if __name__ == "__main__":
    print jie(a)
    print jie(b)