def sum(i ,i2, i3):
    for j in range(6):
        d = i2
        d2 = i
        d3 = j
        if(d <= (pow(2,d3)+d2)): #1+
            if(d != (pow(2,d3)+d2)):
                d4 = j-1
                return sum(d2+pow(2,d4),i2,i3+1) + d4*(pow(10,i3))
            elif(j == 0):
                return pow(10,i3)*5
            else:
                return d3*pow(10,i3)

def encode(str1):
    tmpstr = list(str1)
    out = ""
    for i in range(len(str1)):
        if ord(str1[i]) > 90:
            tmpstr[i] = chr(ord(str1[i])-32)
            # print(tmpstr[i])
        out += str(sum(0,ord(tmpstr[i])-64,0)) + "0"#这里可以看出来以0为分割

    return out

# aa = ['14', '5', '123', '54', '3', '123', '54', '524', '24', '513', '514', '13', '']
# aa = aa[:-1]
# print(aa)
# kk = []
# for i in aa:
#     ans = 0
#     for j in i:
#         if j == '5':
#             ans += 2**0
#         else:
#             ans += 2**(int(j))
#     kk.append(ans)
# print(kk)

# for i in kk:
#     b = i+64+32
#     if(b>90):
#         print(chr(b),end='')
#     else:
#         print(chr(b-32),end='')

# print('\n')
# print(len("ranqhnqutksj"))
# 140501230540301230540524024051305140130
print(encode("ranqhnqutksj"))
print("ISCC{"+"ranqhnqutksj}")