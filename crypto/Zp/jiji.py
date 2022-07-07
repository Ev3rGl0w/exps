def Jacobi(m, N):
	p = 1
	q = 1
	while True:
		if m > N:
			m %= N
		while m % 2 == 0:
			m //= 2
			if (N % 8 == 1) or (N % 8 == 7):
				p *= 1
			elif (N % 8 == 3) or (N % 8 == 5):
				p *= -1
		if m == -1:
			if N % 4 == 1:
				p *= 1
			elif N % 4 ==3 :
				p *= -1
			break
		if m == 1:
			break
		q = N
		N = m
		m = q
		if (N - 1) * (m - 1) % 8 != 0:
			p *= -1
	return p

if __name__ == '__main__':
	p = 9628436377784788667
	q = 16394017319585898011
	n = 157848752737934733984337076039050641337

	a = 201902723007
	y = a * pow(10, 18)
	y1 = y
	y2 = y
	while (Jacobi(y1, p) != -1) or (Jacobi(y1, q) != -1):
		y1 += 1
	while (Jacobi(y2, p) != -1) or (Jacobi(y2, q) != -1):
		y2 -= 1
	y = y1
	if abs(y1 - y) > abs(y2 - y):
		y = y2
	print('y = %d' % y)

	# xi = 65537^i
	M = '10001101'
	C = ''
	for i in M:
		i = int(i)
		xi = pow(65537, i)
		if i == 1:
			c = (y * pow(xi, 2)) %  n
		else:
			c = pow(xi, 2, n)
		C += str(c)
	print('C = %s' % C)