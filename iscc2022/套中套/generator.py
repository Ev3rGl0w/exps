#!/usr/bin/python

import random
import codecs
import gmpy2
import sys
import os

def getRandom(randomlength=4):
	digits="0123456789"
	ascii_letters="abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	str_list =[random.choice(digits +ascii_letters) for i in range(randomlength)]
	random_str =''.join(str_list)
	return random_str


def makeKey(n):
	privKey = [random.randint(1, 4**n)]
	s = privKey[0]
	for i in range(1, n):
		privKey.append(random.randint(s + 1, 4**(n + i)))
		s += privKey[i]
	q = random.randint(privKey[n-1] + 1, 2*privKey[n-1])
	r = random.randint(1, q)
	while gmpy2.gcd(r, q) != 1:
		r = random.randint(1, q)
	pubKey = [ r*w % q for w in privKey ]
	return privKey, q, r, pubKey

def encrypt(msg, pubKey):
	msg_bit = msg
	n = len(pubKey)
	cipher = 0
	i = 0
	for bit in msg_bit:
		cipher += int(bit)*pubKey[i]
		i += 1
	return bin(cipher)[2:]



flaggg=open('ffalg.txt','w')

# secret = input('Plz input the FLAG to generate the question.')
for i in range(50):
	fe = open('enc.txt', 'w')
	fpub = open('pub.Key', 'w')
	fpriv = open('priv.Key', 'w')
	fq = open('q.txt', 'w')
	fr = open('r.txt', 'w')
	
	print(i)
	tt="ISCC{"
	for j in range(3):
		temp=getRandom()
		tt=tt+temp+'-'
	secret = tt[:-1]+'}'
	flaggg.write(secret)
	flaggg.write('\n')
	msg_bit = bin(int(codecs.encode(secret.encode(), 'hex'), 16))[2:]
	keyPair = makeKey(len(msg_bit))
	pub_str = '['+', '.join([str(i) for i in keyPair[3]]) + ']'
	fpub.write(pub_str)
	#print ('pub.Key: ' + pub_str)
	enc =  encrypt(msg_bit, keyPair[3])
	#print ('enc: ' + str(int(enc, 2)))
	fe.write(str(int(enc, 2)))
	priv_str = '['+', '.join([str(i) for i in keyPair[0]]) + ']'
	#print ('priv.Key: ' + priv_str)
	fpriv.write(priv_str)
	#print('q: ' + str(keyPair[1]))
	fq.write(str(keyPair[1]))
	#print('r: ' + str(keyPair[2]))
	fr.write(str(keyPair[2]))
	name="misc-example-"+str(i+1)+".zip"
	fe.close()
	fpub.close()
	fpriv.close()
	fq.close()
	fr.close()

	# os.system("zip -r -P'wELC0m3_T0_tH3_ISCC_Zo2z' tzt2.zip enc.txt generator.py priv.Key pub.Key q.txt r.txt")
	# os.system("zip -r ./output/{}.zip tzt.png tzt2.zip".format(name))
	

flaggg.close()



