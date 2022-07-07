import os

for i in range(2):
    k = os.popen("curl http://47.104.243.99:10000/show.php | grep 'value'")
    print(k.read())