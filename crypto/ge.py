import numpy

def cal(tmp2,tmp1):
    tmp2 = numpy.array(tmp2)
    tmp1 = numpy.array(tmp1)
    dist = numpy.sqrt(numpy.sum(numpy.square(tmp2 - tmp1)))
    return dist

num = 1000
tmp1 = [25/7,16,47/4]

for i in range(-50,50):
    for j in range(-50,50):
        for k in range(-50,50):
            tmp2 = [10*i+11*j+13*k,9*i+10*j+7*k,10*i+12*j+21*k]
            if num > cal(tmp2,tmp1):
                num = cal(tmp2,tmp1)
                ans = tmp2
            
print ans
print num