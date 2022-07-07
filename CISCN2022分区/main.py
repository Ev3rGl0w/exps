import mylib.pyd
from mylib.pyd import CheckStatus as CS, START, END, WALL, ROAD
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
        if map_[i] not in (START, END, WALL, ROAD):
            exit(0)

    key = input('Input key:').encode()
    # match mylib.check(map_, list(key)):
    #     case CS.FAIL:
    #         print('Wrong key')
    #     case CS.SUCCESS:
    #         print('Congratulations!!! Your flag is: `flag{md5(key)}`')
    #     case CS.ERROR_CIPHER_LEN | CS.ERROR_DATA_LEN | CS.ERROR_FMT | CS.FATAL_ERROR:
    #         print('Something wrong, can you figure out?')
    print('Bye~')


if __name__ == '__main__':
    dllName = "\\util.dll";
    dllABSPath = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + dllName;
    dll = cdll.LoadLibrary(dllABSPath);
    os.environ['path'] += ';C:\\Users\\lsp\\Desktop'
    main()