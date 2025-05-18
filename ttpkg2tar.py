#script made with my own research and by taking inspiration from previous ones:
#https://github.com/Rupan/tomtom/
#https://github.com/egonalter/R-Link-RE

import sys
import os

file_block_length=102400
file_interblock_length=20

for file_name in sys.argv[1:]:
    if os.path.isfile(file_name):
        print("Opening",file_name)
        f=open(file_name,mode="rb")#essentially ttpkg is a tar file with extra data

        h=f.read(8)
        header={"flags":[]}
        if h==b"_unprot_":#sometimes it is the first thing in the ttpkg / don't know what it does -> skip
            header["flags"].append("_unprot_")
            h=f.read(8)
        if int.from_bytes(h[4:],byteorder="little")!=0:#header before the archive size / could be present or not
            hn=int.from_bytes(h[:4],byteorder="little")#number of header fields
            hs=int.from_bytes(h[4:],byteorder="little")#length of the header
            h=f.read(hs)
            h=h.split(b"\x00")
            for n in range(hn):#extract the fields
                hi=h[n].split(b"=",1)
                header[hi[0].decode("utf-8")]=hi[1].decode("utf-8")
            h=f.read(8)

        header["size"]=int.from_bytes(h,byteorder="little")#archive size from this point to the end of file without counting the interblocks

        file_interblock_signature=[f.read(file_interblock_length)]#first interblock (they are 20 octets long and there is one every 102400+20 octets -> file system stuff?)

        h=f.read(8)#header after the archive size / same kind as the first header
        hn=int.from_bytes(h[:4],byteorder="little")
        hs=int.from_bytes(h[4:],byteorder="little")
        h_delta=hs+8
        header["size"]-=h_delta
        h=f.read(hs)
        h=h.split(b"\x00")
        for n in range(hn):
            hi=h[n].split(b"=",1)
            header[hi[0].decode("utf-8")]=hi[1].decode("utf-8")

        print("Header data:",header)
        input("Press any key to continue...")

        tar_name=file_name[::-1].split(".",1)[1][::-1]+".tar"
        tar=open(tar_name,mode="wb")
        p=h_delta
        while p<header["size"]+h_delta:
            d=file_block_length-(p%file_block_length)#don't forget the header after the archive size count for the distance to the next interblock
            p+=d
            tar.write(f.read(d))#copy until next interblock
            file_interblock_signature.append(f.read(file_interblock_length))#interblock could be the same as the first but in other case it is completely different
        f.close()
        tar.close()

        print("Archive created as",tar_name,"\n")
    else:
        print(file_name,"doesn't exist")
