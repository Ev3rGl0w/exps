s = '=IkMBb+=gF2/Try5PCUruw1j'
print(len(s))
a = list('012345678901234567890123')
z = False
k = 0
for i in range(5, -1, -1):
    if not z:
        for j in range(3, -1, -1):
            a[j * 6 + i] = s[k]
            k += 1
        z = True
    else:
        for l in range(0, 4):
            a[l * 6 + i] = s[k]
            k += 1
        z = False
for i in range(len(a)):
    print(a[i],end='')