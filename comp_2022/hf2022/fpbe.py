import struct
from z3 import *
# import z3
solver = Solver()
arg1, arg2, arg3, arg4 = Ints("arg1 arg2 arg3 arg4")

solver.add(arg4 * 52366 + arg3 * 29179 + arg2 * 64392 + arg1 * 28096 == 209012997183893)
solver.add(arg4 * 37508 + arg3 * 44499 + arg2 * 27365 + arg1 * 61887 == 181792633258816)
solver.add(arg4 * 59154 + arg3 * 25901 + arg2 * 32808 + arg1 * 56709 == 183564558159267)
solver.add(arg4 * 62010 + arg3 * 31886 + arg2 * 51779 + arg1 * 33324 == 204080879923831)

if solver.check() == sat:
    flag = ''
    res = solver.model()
    for arg in [arg1, arg2, arg3, arg4]:
        flag += struct.pack("<I", res[arg].as_long()).decode()
    print(flag)