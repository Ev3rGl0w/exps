from z3 import *

a = Int('a')
b = Int('b')
c = Int('c')
d = Int('d')
e = Int('e')
f = Int('f')
g = Int('g')
v = Int('v')
#a, b, c, d, e, f, g, v= BitVecs('a b c d e f g v', 64)
s = Solver()

s.add(b + 7 * a - 4 * v - 2 * c == 0x2060BF585)
s.add(5 * c + 3 * b - a - 2 * v == 5986700496)
s.add(2 * a + 8 * c + 10 * v - 5 * b == 0x449C83E5E)
s.add(7 * v + 15 * a - 3 * c - 2 * b == 0x7B13C2C5D)
s.add(15 * d + 35 * g - e - f == 0xF919FB032)
s.add(38 * f + d + g - 24 * e == 0x7060508FA)
s.add(38 * e + 32 * d - f - g == 0x124F561560)
s.add(d + 41 * f - e - 25 * g == 0x51C97373E)

if s.check() == sat:
    result = s.model()
print(result)
for i in result:
    print("%s = 0x%x" % (i, result[i].as_long()))

#这里吧上面的结果里的a b c d e f g 两位 两位写过来
flag = [0x7b, 0x57, 0x55, 0x47,
        0x5a, 0x50, 0x56, 0x4e,
        0x47, 0x2d, 0x54, 0x57,
        0x4a, 0x44, 0x48, 0x4f,
        0x41, 0x4d, 0x2d, 0x45,
        0x54, 0x55, 0x55, 0x41,
        0x56, 0x52, 0x57, 0x7d]
v = 0x49534343
for i in range(len(flag)):
    print(chr(flag[i]),end='')