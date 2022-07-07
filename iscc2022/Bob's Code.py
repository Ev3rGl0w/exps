Str = '.W1BqthGbebDpcM51X1tLp.G5VoYzNtG00XFpEVhR5oVltdOU0XYRPo1sboF0.'
str3 = ".U1ZorfEzczjJrKZWVMxgr.WVTmDfHmNBZY2PVmLrTmUnorLZ3YVrKmE5imD0."

flag = list(str3)
source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
mode = list(r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
des = list(source)
for i in range(5, 19):
	v12 = des[i]
	des[i] = source[i+26]
	des[i+26] = v12
print(des)
pp = ''.join(des)

for i in range(len(flag)):
	flag[i] = mode[pp.find(flag[i])]
print(''.join(flag))
# for i in range(len(flag)):