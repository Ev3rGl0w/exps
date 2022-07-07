# -*- coding: UTF-8 -*-
import socket
import _thread
def print_recv(s):
    while(s):
        result = s.recv(1024)
        if(result):
            print(result)
        else:
            return
s = socket.socket()
host = '0.0.0.0' # 获取本地主机名
port = 1000 # 设置端⼝
s.bind((host, port)) # 绑定端⼝
s.listen(1)
while True:
    c, addr = s.accept()
    print ('连接地址：' + str(addr))
    try:
        result = c.recv(1024)
        if(result):
            print(result)
        else:
            pass
        while(True):
            c.send('\n')
    except Exception as e:
        print(e)
        print("Disconnect")
        c.close()