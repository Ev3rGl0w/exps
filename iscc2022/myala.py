import base64
string = ['I', 'S', 'C', 'C', 'Y', 'E', 'S']
string2 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

cp = 'rJFsLqVyFKZcI5gEH1DtU6MLCs51q4AoYPmmCrv='  # base64
flag = ''
for i in range(0, len(cp)):
    if cp[i] in string2:
        v = string2.find(cp[i])
        v2 = string2.find(string[i % 7])
        out = string2[v - v2]
        flag += out
    else:
        flag += cp[i]
print(flag)
flag = base64.b64decode(flag)
print(flag)
flag = list(flag)
for o in range(len(flag)):
    flag[o] = chr(flag[o] ^ ((o % 7) + 1))
print(''.join(flag)[:-4])