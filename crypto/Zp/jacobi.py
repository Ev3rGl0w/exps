N = 157848752737934733984337076039050641337
#(a/b)
def func1(a,b):
	a = a%b
	if a == -1 or a==b-1:
		return pow(-1,(b-1)/2)
	elif a==2:
		return pow(-1,(b*b-1)/8)
	else:
		return pow(-1,(a-1)/2*(b-1)/2)*func1(b,a)

print(func1(11,N))
