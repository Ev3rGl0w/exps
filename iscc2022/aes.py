# -*- coding: utf-8 -*-
"""
Created on Tue May 10 16:03:27 2022

@author: JUXY
"""

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import hashlib
import base64


#例子如下
#明文:str(binascii.b2a_hex(str.encode('tuya49368a48b746')))[2:-1]
#密文:51506024af73925e15da8873afb08f9d
#key:str(binascii.b2a_hex(str.encode('8sHRRhqNAdXnSvpA')))[2:-1]
#iv:str(binascii.b2a_hex(str.encode('8sHRRhqNAdXnSvpA')))[2:-1]

#如果text不足16位的倍数就用"00"补足,即采用NoPadding方式补齐
def PKCS_zero(text):
    newbytes = '00'
    if len(text) % 32:
        add = 32 - (len(text) % 32)
        add = add >> 1
    else:
        add = 0
    text = text + newbytes * add
    return text
    
# 加密函数
def AES_CBC_encrypt(text,key,iv):
    print("AES_CBC_encrypt")
    print(" key  :", key, type(key))
    print(" iv   :", iv, type(iv))
    print("plain :", text, type(text))

    mode = AES.MODE_CBC
    text = PKCS_zero(text)
    text = bytes.fromhex(text)
    print("plain :", bytes.hex(text),type(text))
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)

    cryptos = AES.new(key, mode, iv)
    cipher_text = bytes.hex(cryptos.encrypt(text))
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串

    print("cipher:", cipher_text, type(cipher_text))
    print("************************************************")
    return cipher_text
    # 解密后，去掉补足的空格用strip() 去掉
   
#AES-CBC解密
def AES_CBC_decrypt(text,key,iv):
    print("AES_CBC_decrypt")
    print(" key  :", key, type(key))
    print(" iv   :", iv, type(iv))
    print("plain :", text, type(text))

    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)

    plain_text = bytes.hex(cryptos.decrypt(text))

    print("cipher:", plain_text, type(plain_text))
    print("************************************************")

    return plain_text
print(AES_CBC_decrypt(base64.b64decode(b"/c/ua543HrY7vfzoYfHz+nfXEsDVQ4ph+yD9gu5mAlY="),'S0BlMjAyMiUleQ==',b'SSZWMjAyMioqKg=='))

from Crypto.Util.number import *
print(long_to_bytes(0x6d6e69695f66743637382655265e62765f))
