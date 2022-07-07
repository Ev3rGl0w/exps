from Crypto.Cipher import AES
import base64
def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def exp(a,e):
    for i in range(1,6):
        for j in range(1,6):
            for k in range(1,6):
                for l in range(1,6):
                    for m in range(1,6):
                        b={0,i,j,k,l,m}
                        c=[0,i,j,k,l,m]
                        if len(b)!=6:
                            continue
                        d=""
                        for n in range(8):
                            for o in c:
                                d+=a[o][n]
                        cipher=AES.new(b'QERAPG9dPyZfTC5f',AES.MODE_CBC,b'aUBTJjg4Q2NDLg==')
                        plaintext=cipher.decrypt(base64.b64decode(d))
                        s=""
                        for p in range(1,6):
                            if p!=e:
                                s+=str(c.index(p)+1)
                            else:
                                s+=str(c.index(p)+1)
                                s+="1"
                        if len(s)!=6:
                            s="1"+s
                        if s.encode() in plaintext:
                            print("ISCC{"+unpad(plaintext).decode()+"}")
    return  

a=""
while len(a)!=48:
    a="o4O6+uY=/gmnBpL=CKa+pm3=Tug9B9p=2McS3PT=WAVDhTIQ"
b=[]
for i in range(6):
    b.append(a[i*8:(i+1)*8])
a=[""]
c=0
for i in range(6):
    if b[i][7]!="=":
        a[0]=b[i]
        c=i
    else:
        a.append(b[i])
print(a)
exp(a,c)