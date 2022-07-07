import gmpy2
from Crypto.Util.number import *

p = 9628436377784788667
q = 16394017319585898011
N = 157848752737934733984337076039050641337
g = 1 + N
c = import gmpy2
from Crypto.Util.number import *

p = 9628436377784788667
q = 16394017319585898011
N = 157848752737934733984337076039050641337
g = 1 + N
c = 16378542863548780534284115914366442618038552415326247441212079536531580851424
φN = (p - 1) * (q - 1)
m = ((gmpy2.powmod(c, φN, N**2) - 1) // N * gmpy2.invert(φN, N)) % N
print(long_to_bytes(m))
φN = (p - 1) * (q - 1)
m = ((gmpy2.powmod(c, φN, N**2) - 1) // N * gmpy2.invert(φN, N)) % N
print(long_to_bytes(m))