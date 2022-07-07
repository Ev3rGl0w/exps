f = open('./fffflllaag.dat', 'rb').read()


for i in range(0xff):
    new = open('./flag{}.zip'.format(i), 'ab')
    # letter = chr(i)# 'k1eAn'
    # secret = int(letter,16)
    secret = i
    # print(secret)
    for i in f:
        kk = int(i) ^ secret
        # print(kk)
        new.write(int(kk).to_bytes(1, 'big'))
    # for secret in range(0,0xff):
    #     new = open('./flag{}.zip'.format(secret), 'ab')
    #     for i in f:
    #         print(i)
    #         n = int(i) ^ secret
    #         new.write(int(n).to_bytes(1, 'big'))

