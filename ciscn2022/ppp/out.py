f=open('usbdata4.txt','r')
fi=open('out4.txt','w')
while 1:
    a=f.readline().strip()
    if a:
        if len(a)==16:
            out=''
            for i in range(0,len(a),2):
                if i+2 != len(a):
                    out+=a[i]+a[i+1]+":"
                else:
                    out+=a[i]+a[i+1]
            fi.write(out)
            fi.write('\n')
    else:
        break

fi.close()
