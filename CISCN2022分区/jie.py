# import mylib
# from mylib import CheckStatus as CS, START, END, WALL, ROAD
import os

def main():
    if not os.path.exists('data'):
        print('Missing file: data')
        exit(0)
    with open('data', 'rb') as f:
        data = f.read()
    map_ = list(data)
    cipher = list(b'suta-to')
    for i, ch in enumerate(map_):
        map_[i] = ch ^ cipher[i % len(cipher)]
        if map_[i] == 83:
            map_[i] = 'S'
        elif map_[i] == 35:
            map_[i] = '0'
        elif map_[i] == 32:
            map_[i] = '1'
        elif map_[i] == 69:
            map_[i] = 'X'
        for i in range(101):
            for j in range(101):
                print(map_[i*101+j],end='')
            print('\n')
if __name__ == '__main__':
    main()