import sys
import os
import json

#Tool to parse the data from SD/TOMTOM.xxx/device/[Serial number]/factory.dat in an SD card for an R-Link 1 device

#How to use:
#python factory_dat_parser.py [path to factory.dat]

#For more information:
#https://wiki.freebsd.org/FlattenedDeviceTree
#https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html
fn=sys.argv[1]
if not os.path.isfile(fn):
    print("File does not exist")
    exit()

f=open(fn,"rb")

data={}

#header
data["header"]={}
data["header"]["magic"]={"hex dump":f.read(4).hex()}
data["header"]["size"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["off_dt_struct"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["off_dt_strings"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["off_mem_rsvmap"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["version"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["last compatible version"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["boot_cpuid"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["size_dt_strings"]=int.from_bytes(f.read(4),byteorder="big")
data["header"]["size_dt_struct"]=int.from_bytes(f.read(4),byteorder="big")

#data
data["data"]={}
path=[data["data"]]
olabel=data["header"]["off_dt_strings"]
p=data["header"]["off_dt_struct"]
while p<data["header"]["off_dt_struct"]+data["header"]["size_dt_struct"]:
    p+=(4-p)%4
    f.seek(p)
    c=f.read(4)
    p+=4
    if c==b"\x00\x00\x00\x01":#begin node
        l=f.read(1)
        while l[-1]!=0:
            l+=f.read(1)
        l=l[:-1].decode("utf-8")

        path[-1][l]={}
        path.append(path[-1][l])
        
    if c==b"\x00\x00\x00\x02":#end node
        path=path[:-1]

    if c==b"\x00\x00\x00\x03":#property
        length=int.from_bytes(f.read(4),byteorder="big")
        plabel=int.from_bytes(f.read(4),byteorder="big")
        p+=8+length
        
        d=f.read(length)
        if length>4:
            if d[-1]==0:
                d=d[:-1]
            d=d.decode("utf-8")
        else:
            d=int.from_bytes(d,byteorder="big")
        
        f.seek(olabel+plabel)
        l=f.read(1)
        while l[-1]!=0:
            l+=f.read(1)
        l=l[:-1].decode("utf-8")

        path[-1][l]=d

    #b"\x00\x00\x00\x04" -> NOP

    if c==b"\x00\x00\x00\x09":#end
        break
f.close()

f=open(fn+".json","w")
json.dump(data,f,indent="\t")
f.close()

print("Result can be found in "+fn+".json")
