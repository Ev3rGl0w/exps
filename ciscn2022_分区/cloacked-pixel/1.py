#coding:utf-8
import os
import string

# creat password
password = []
pd_element =  list(string.ascii_letters) + list(string.digits)
for i in pd_element:
	if i != 'b':
		continue
	for j in pd_element:
		#if j != '1':
			#continue
		for k in pd_element:
			for m in pd_element:
				for nn in pd_element:
					password.append(i+j+"k1eAn"+k+m+nn)
					#pd = i+j+k+m+"k1eAn"
					#print "password = %s " %pd

n = 0
file_name = '1.png' # 解密的图片
out_file_1 = 'out.txt' # lsb中间文件
out_file_2 = 'result.txt' # result结果记录文件
for pd in password:
	out_data_2= open(out_file_2,'a')
	try:
		print "total try {} times\ntrying: {}".format(n,pd)
		argv = r'python lsb.py extract ' + file_name  + ' ' + out_file_1 + ' '+ pd 
		lsb  =  os.popen(argv,'r')
		data = lsb.read()
		lsb.close()
		print "{} SUCCESS".format(pd)
		out_data_1 = open(out_file_1,'r')
		data = out_data_1.read().strip('\n')
		out_data_2.write(data+'\n')
		n += 1
		break
	except:
		print "{} ERROR".format(pd)
		n += 1
	out_data_2.close()

