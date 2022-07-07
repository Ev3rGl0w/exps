from hashlib import sha256
import random, string
import tempfile
import os, sys

strgen = lambda n: ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(n))

def pow():
    prefix = strgen(5)
    data = input("sha256(\"{}\"+input) starts with 20 bits of zero: ".format(prefix))
    hash = sha256((prefix + data.strip()).encode("ascii")).hexdigest()
    return True if hash.startswith("00000") else False

def go():
    line = sys.stdin.readline() 
    data = ""
    while True:
        if line.strip() == "IMDONE":
            break
        data += line
        line = sys.stdin.readline() 
    fd, path = tempfile.mkstemp()
    with open(fd, "w") as f:
        f.write(data)

    p = os.popen("zic {}".format(path))
    print(p.read())
    os.unlink(path)
    return


welcome1 = """\
Welcome to my timezone compile server.
The server will compile your time conversion information files
to standard tzfile(5). For more information, please RTFMan.
The lsb_release information is:"""

welcome2 = """\
The uname information is:"""

welcome3 = """\
End your input with "IMDONE"."""

if __name__ == "__main__":
    if not pow():
        print("Please proof yourself first!")
        exit(0)
    print(welcome1)
    os.system("lsb_release -a")
    print(welcome2)
    os.system("uname -a")
    print(welcome3)
    go()

