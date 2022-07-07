rec_msg = b'<pH\x86\x1a&"m\xce\x12\x00pm\x97U1uA\xcf\x0c:NP\xcf\x18~l'
out_s = [] 
flag = b'cazy{'
out_flag = []
for i in range(0, len(rec_msg)):     # 获取字节数组字数据，注意引号 ' ' 之间有一个空格
    out_s.append(hex(int(rec_msg[i])))
    
for i in range(0,len(flag)):
    out_flag.append(hex(int(flag[i])))

print(out_flag)
print(out_s)

key = ''
for i in range(len(flag)):
    key += chr(int(out_s[i],16) ^ int(out_flag[i],16))
print(key)

new_key = key*6

flag1 = ''
for i in range(len(rec_msg)):
    flag1 += chr(int(out_s[i],16)^ord(new_key[i]))

print(flag1)