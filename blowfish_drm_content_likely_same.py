#Tool to compare 2 TomTom encrypted files and guess if the contents are likely the same (no META code required)

#How to use:
#python blowfish_drm_content_likely_same.py [path to file 1] [path to file 2]

import sys
from os import path

if len(sys.argv)<3:
    print("Too few arguments")
    exit()
if len(sys.argv)>3:
    print("Too many arguments")
    exit()
fn1=sys.argv[1]
fn2=sys.argv[2]

if not os.path.isfile(fn1):
    print(fn,"does not exist")
    exit()
    
if not os.path.isfile(fn2):
    print(fn,"does not exist")
    exit()

block_length=0x400

f1=open(fn1,"rb")

if f1.read(5)==b"TTDRM":
    print("File not supported yet")
    exit()
f1.seek(-4,2)
sign_length=int.from_bytes(f1.read(4),"little")#0x498
if sign_length>0x400:
    print("Data length too big - signature part 1")
    exit()
f1.seek(-(sign_length+0x0c),2)
end1=f1.tell()
sign2_length=int.from_bytes(f1.read(4),"little")#0x90
if sign2_length>=0x1c:
    print("Data length too big - signature part 2")
    exit()
end1-=4*(sign2_length+5)
f1.seek(0)

f2=open(fn2,"rb")

if f2.read(5)==b"TTDRM":
    print("File not supported yet")
    exit()
f2.seek(-4,2)
sign_length=int.from_bytes(f2.read(4),"little")#0x498
if sign_length>0x400:
    print("Data length too big - signature part 1")
    exit()
f2.seek(-(sign_length+0x0c),2)
end2=f2.tell()
sign2_length=int.from_bytes(f2.read(4),"little")#0x90
if sign2_length>=0x1c:
    print("Data length too big - signature part 2")
    exit()
end2-=4*(sign2_length+5)
f2.seek(0)

if end1!=end2:
    print("Contents have not the same length:",end1,"!=",end2)
    print("Contents aren't likely the same")
    exit()

if end1<=block_length:
    print("Not enough content to test if they are likely the same")
    exit()

b1=f1.read(8)
b2=f2.read(8)

p=block_length
cl=0
while p<=end1:
    f1.seek(p)
    f2.seek(p)
    l=min(8,end1-(p+8))
    cl+=l
    bc1=f1.read(l)
    bc2=f2.read(l)
    r1=bytes(a^b for a,b in zip(bc1,b1[:l]))
    r2=bytes(a^b for a,b in zip(bc2,b2[:l]))
    if r1!=r2:
        print("Mismatch between addresses",p,"and",p+l,": results",r1.hex(),"!=",r2.hex())
        print("Contents aren't likely the same")
        exit()
    p+=block_length

print("Contents have the same length")
print("No mismatch found over",cl,"bytes")
print("Contents are likely the same")
