#Tool to decrypt TomTom file with a V1 DRM

#require cryptography: python -m pip install cryptography

#How to use:
#python blowfish_drm_decrypt.py [path to file] "[META code]"

import sys
import os

from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, modes

if len(sys.argv)<3:
    print("Too few arguments")
    exit()
if len(sys.argv)>3:
    print("Too many arguments")
    exit()
fn=sys.argv[1]
meta=sys.argv[2].split(";")[0].replace(" ","")

if not os.path.isfile(fn):
    print(fn,"does not exist")
    exit()
if len(meta)!=32:
    print(meta,"is not a META code")
    exit()
try:
    meta=bytes.fromhex(meta)
except:
    print(meta,"is not a META code")
    exit()
    
f=open(fn,"rb")

if f.read(5)==b"TTDRM":
    print("File not supported yet")
    exit()
f.seek(-4,2)
sign_length=int.from_bytes(f.read(4),"little")#0x498
if sign_length>0x400:
    print("Data length too big - signature part 1")
    exit()
f.seek(-(sign_length+0x0c),2)
end=f.tell()
sign2_length=int.from_bytes(f.read(4),"little")#0x90
if sign2_length>=0x1c:
    print("Data length too big - signature part 2")
    exit()
end-=4*(sign2_length+5)
f.seek(0)

g=open(fn+".decrypted","wb")
block_length=0x400
b_iv=b"tomtomiv"
cipher = Cipher(algorithms.Blowfish(meta), modes.CFB(b_iv))
while True:
    decryptor = cipher.decryptor()
    delta=max(0,f.tell()-end+block_length)
    b=f.read(block_length-delta)
    g.write(decryptor.update(b))
    g.write(decryptor.finalize())
    if delta>0:
        h=open(fn+".footer","wb")
        h.write(f.read())
        h.close()
        break
f.close()
g.close()

print("File decrypted")
