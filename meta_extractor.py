#Tool to extract blowfish/meta key from mct/dct file

#require cryptography: python -m pip install cryptography

#How to use:
#python meta_extractor.py [path to mct file] MediaID=[SD card CID]
#python meta_extractor.py [path to dct file] MachineID=[Serial number]
#python meta_extractor.py [path to dct file] DeviceID=[device id]

import sys
from os import path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from cryptography.hazmat.primitives.hashes import Hash, MD5

CRC7t=[0,9,18,27,36,45,54,63,72,65,90,83,108,101,126,119,25,16,11,2,61,52,47,38,81,88,67,74,117,124,103,110,50,59,32,41,22,31,4,13,122,115,104,97,94,87,76,69,43,34,57,48,15,6,29,20,99,106,113,120,71,78,85,92,100,109,118,127,64,73,82,91,44,37,62,55,8,1,26,19,125,116,111,102,89,80,75,66,53,60,39,46,17,24,3,10,86,95,68,77,114,123,96,105,30,23,12,5,58,51,40,33,79,70,93,84,107,98,121,112,7,14,21,28,35,42,49,56,65,72,83,90,101,108,119,126,9,0,27,18,45,36,63,54,88,81,74,67,124,117,110,103,16,25,2,11,52,61,38,47,115,122,97,104,87,94,69,76,59,50,41,32,31,22,13,4,106,99,120,113,78,71,92,85,34,43,48,57,6,15,20,29,37,44,55,62,1,8,19,26,109,100,127,118,73,64,91,82,60,53,46,39,24,17,10,3,116,125,102,111,80,89,66,75,23,30,5,12,51,58,33,40,95,86,77,68,123,114,105,96,14,7,28,21,42,35,56,49,70,79,84,93,98,107,112,121]
BASE32t="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

def crc7(data):
    crc = 0
    for b in data:
        crc = CRC7t[((crc<<1)&0xFF) ^ b]
    return crc

#extracted from system-update_3198541_all.ttpkg -> libttn.so -> address 0x983174 - 0x983E0D
Nk=["8eb7e533ae188f853a949da949c1ce953f0d6db8777b82ee5f7e5b4349e82ceddff9a029eb522c0d117094d5e65d591cecc87a5b34220b0385e1c8fd67f179b3300c1beaf7fc60728446dbc734e56bdc10a2d15b8fb92606c5d33cf9adac31a9c5fd54b7bb77ab8b4fb3552bc854824f1303847adffcb25a94a5cd7e941cbc63",
    "8e1915faa19c5e3286ee6410e5e81e11a49382979bfd29b8b46c3e797aa47875dfa6e9ef55f96db0b6c7cde95d5897470f385307615423c37be08b6b464c15d5b9d9aa1831999054b614a0387c569259a22aac04e4cea67be596989f3645af80b88c846ce3d007ff436d0465c78bb4f224ea4514e3aed3f676cac1c239ad879f",
    "9a76c3ef34c954b4508c2c14f42bfa027717a0bdbd51b601e153684921dad3ada67c2553e3b5b5a0b8d21115f5bff3dc72b37a17eed26d69ee7807d3577238fe4005ac3c72d3ebefdee1ac7efc7a702dc7f3bf207c1eedffeac112419c69de681533babf5d906c5f338b3babb5b310f3c7c0b2570feb19b596eff394f7967a95",
    "8cb08ac561c33572493adbb96e47faf5b3a8abc218c245a01945a01a1514509f06ca6adff3af4eacc3a26daedbf65dfddc4155a1b99ee0e3ef57076710bfc798425e83990d5b4f68983c2f48ce4b592fdd904c5e102e62f00407f5bedf2ad54ec892228e883dee73596c8dcc629e8836b4e9af5271e34b5e6da518e14ff20521",
    "94ed68e5d22ed4dd405654d132389798211ae7dea2b4b97b34e848f45a3a68d2c733843104d710fbc02c76a4d7e94e7aeba8ab6cc0956d197cd6cbdec10bc6594a4c698f7ce0b0d62e8246698a122e2f00e3d832ecd2a2e5fed9efdf3f5a7c32022dd34c25b1b78daa6fafd199f35ad05ec66a0c1a3605ecd08a20b94a4d5997",
    "838da3a16a8928b309895858a47e6b10d8e969cf8a1a9b85d6c2bb86c8698a1e608735d0afba796c9448ee9fc4ca1742c3da4ccbf426e1e0e88257e1575dbb6b3802b671dcadb0afa07091ade02a4c7ed2a1328a6f6d0f0e2b6fbc6918626c491b8c64bd6d5f6157d66fa5d2e85e608d5b76af03677f195906907183ed941d27",
    "ad9f3f0c1d3a79237a90fef3a67d74178cc6217161e3001217461eac2e9015ec506c73c501507fb719f5c958b3f68a715d7fba663a8363952eb991aa48fc2aa8a98ee1b5b42ab1967cab03eab3be60bb2ec26cbba1be048f9d3914f2286e7f0e2d1588bfc7cd0f9906c94d91c809711258993c4d624107a4368c49a81c45baa7",
    "cfb88bd5cd38d4cc3f0cf7367e7ea6293683a67edb4fabb1f061a90bbd9f302fac7aa1d97169a51002d70f32b579171ba7050f86232dd9237eb0e005aeacac9c909dbc7e39375cd4c876d40cab51037e78718ade3736c965fb9f2f9de58aef9271c5c7364a1ddb55ea0faedc2cb8602345d31572bbabe4573b1371be9b952a27",
    "93bacc6c028fb4fa5955ad09fd572a462357a286093b5c078ad12c9ce5f92bd09ae88afaece3a01d707d9d43eb60a23ded912d2b09524b64af9fbb026ce94ca38dcbbdaf622621fd4224b7dff5c18658b4c18652a0f52b28c1809e4169926a606a873239ae28a36abe9760b6def13eff76bccfea63f4e1fd696d61043e18a5e5",
    "8a407458269c51639554128581af45279d94c8d72d8f8ce239229bd8f6ef3f3291b04651b5c7201dcddfe3553a0cc8dddf2be594b110ab5909f32a8a239b248f05f29f8a4a3d84cd41e87086add2e4ec6ba8defdd604b5720c8cc955d655b881b7afb94fc7ff7ac43deaf44de3dc323982e2ffdcd33683e74f2253c6c4b73483",
    "8c345a09229da1a7445cef3868277e9b65e8bf3238f8c373fca8eddc47310341fa59425406768b65b9d1a9c4e4c36dad68fa4a60e9d1dc64fa90f69e8439e06eccfc4b27729096a28307804d612c223220ad440db3d6c8398e800abcd18b44b789f2e9f05ff34f002241a8111ada4ded17f073c43884a253c9149dc6df319ebb",
    "8220ec079461e75056bba886294d5926db2ee4a41b740da326cf35c2f761b84138feebc9f7d54dbe4f89854f15c98ec98fb0f67d21a66a594626c5f5f67b07df69f6bb9045cbe5ec7d53515e565f517591270a60267b031f4ecf93faf5b65c5a5e2824cf6a572959f3c874bab0bd8d2742ff381fa59b8ae881ee910537d9ee9b",
    "9cce70862860b90ce912af67b6996bc766dcafaad380f9aa263d36483a717dc8f7ed379534a01aee822966cc9f4e5dca59be6de746157ef04b3087dc7e09b33fca64c99f1a9512fa097de0d01b6f0f4444c2f9d2eae0af7b56c154c939feb6d72e15bc26353b0c797543134293f10dd57e401cf345edba56b0ba9c804b9d427b",
    "9813ccd27e73256ce2efcc296376393b7c61f88eb803fef1f83477bffc07189dd0fac365dd47785964f80d769cf4624eb0ba52c2b33fceb74c419ca311e4aade82a04bdc042f388aeb81999ef73bb57cbbf10247ea6ad4fceb48fc2c5eff6d98f624825c5764b95b732637322cca9dc81bf64ae57dd2346ce91e71a50b40a051",
    "9de0450fe252a62f5ec21df30f94ba919d300cbd884582454731c1f57246c52d673479bfab02c3df09c77f88e80d898dd5c59762e1b13105e86ee11cc32beee06ba78a637fcd2e09c923b110326ebc26003521ec30adc38394ac2add7b67624a83b0de1f3fb0fdfa5d33c6293e237075d1138bd0a9e52a7e5e658ac798bdc39b",
    "919f8e09a0e02c7dfcba7e8dc5d36dfef76d2d8733ba777c8de34adc6aec0a9fefc68a2cdde7bd242a50cfb637c8e763e19b4d4ddd8bcc896f85e6fd4dbf9aac74589693a7e849d3a107551698cc0ca22d42f65f02dc788ba664504b72953ff697546621fb0ff9473ba8d342c8049c7bf548acb52f8050cb685b83f81a8356e3",
    "c99399915144c9a790e42fac53014f7ac05c38abbc1fcf215ba2acf5563f4ff83fbca8e1834d9fe6d34c036ba73284de387bdf53a14c792465473e9b7d13836eda05b613a38e3b17fdf9ea5abddf9da350197bf8095b7a7f68a297d4e4e54576dc0433174c42e117f06fd96bd73849cce402c46b8221b8af87c62c4f041b7a4f",
    "88bf467a3031651ad11a4eb3afb7e4d8bfa723f48ac3dcedbf29c78d0c501eb51c5783970f7206fce276f6a47e8824febe6da3af138f0edd22046b2bc5764d47aaf21f215424fb8137182c4340bad8dbfd28a0aa5e3b77bbc06f2bfecc16815d69ff185d9ecdfcd71824c64992ce311867c1ec0f30aa7378a4a4be002fa39585",
    "8df6a4e87bf6e06ee825f036b9a74800386023bc3c3ac722ae2b2a1716f0eabc2226759d2b09fa53cc53c8263f7f212bc9ecb9d0c148db8b28109fe7be108791243a5fbd9b9c9f1186303170cb7e08326bb32977688c5c2ab622efa830f89ec955010d50e7d75248ebed89997471db49bd2c877c22510ebf570a8984aef70459",
    "caf93d1c304a10722f5007b3fb1fc7f22785ab32f928cab64139c32f960ec54ca3174211110136276034ff007d46e73370d834c1524380a8088d32f5831f2572fc3b3a12d53dc075d237522e57877f3bf212fa944b24cdf64793ac22a8747282431e4aea4b23f79db3402d50bf8529aca6d562741cd014b4d17d8f466ceec0b7",
    "829e8ff7fbc2d2978099aa3acb96c0a06facea523f5eff3aa78627377ba914a69e1cbc648597f6c9e6955f9a555a2391b478ee9762f5d4e92efec7e65e31462a6f2ec16627be3ac133a96ee343c468e2ec89abcb03209171bac5b61e023d5fe0f66bac8602c8a0e9f495225ac8c479470b83c489d76689806d20eac0a2e3d565",
    "8af0466ee104dbb16ae70b2f457296975ff1912bab0bdd9cbb83390bd5f4b49369bac0defba8f7be9e61e1b3e1498c3c624785d536461ce74c3af0338b11a0d3e11b0ee22535029a8560890ff9ab4a876d092b9b133a351d24743fdccb64a6144e5094a7797f72605d84fe6d7ba38d31e48dc0155e186bce341c96fcd5167fbf",
    "931f1f2b740dc470ccbe885d9fd351ffccc2039aec0c0c40fbe52df89d4a4535e885b3d28bd55420e26c18a860a7df291076ab0d98d3a924d5abfdd8c8bae13182cd0541122953fb4a0fa545a122fe67b88b7d0dbc4d80c6caf32940d7becf27795ff487af844edc0d853b7269b43e3789e97a8ff6334fb0e226e14b91c5f90f",
    "c657f0ee5ef35a35f1e3a8dfbfcc0a257862853337e6cc78fd5bae17e912b31b7fd26621dad5063f6d793beb60c4909e4746c58cead2c23774381b306305a1f9cb1f89328a285f728991fffd16e92574a7c74b3f992ad4c32c4b388d3b424bd176dd08bc0dbb86cbb5dcd30e3af7a858f9fa7b7c08fd1459cc6fa9096c290103",
    "a520285d1a1cdd6c66226094a4235e57345cc81e49ecafc61046a33dc90a284da40839e8679575b55ce900defb3ea38b762ca18807aeea5289c10f3bb34cd1b7a6de787cf2733edb70034bee7566febfd4abcffecdf188365c6dba565ccce22360caa6d08e7e98ef8d7485663ae394d522176abbc7d3d0e83ca08299d783660d"]

MachineID=""#Serial number, MUID, device-serial or DeviceSerialNumber (2 letters + 10 numbers)
DeviceID=""#DeviceUniqueID in ttgo.bif (10 letters/numbers) (MachineID but shorter + checksum and Base32 encoded)
MediaID=""#SD card CID (same as SDCardId in ttgo.bif?) (16 bytes, passed to the program in hexadecimal form, could try recover the CRC part if missing)

fn=sys.argv[1]
if len(sys.argv)>2:
    for arg in sys.argv[2:]:
        arg=arg.split("=",1)
        if arg[0].lower()=="machineid":
            MachineID=arg[1]
        if arg[0].lower()=="deviceid":
            DeviceID=arg[1]
        if arg[0].lower()=="mediaid":
            MediaID=arg[1]

f=open(fn,"rb")
nKey=int.from_bytes(f.read(1))
f.seek(4)
data=f.read(0x80)
f.close()

N=int.from_bytes(bytes.fromhex(Nk[nKey]),byteorder="big")

#extracted from system-update_3198541_all.ttpkg -> libttn.so -> address 0x983E10 - 0x983E13
E=2**16+1

try:#decrypt certificate
    CERT=RSAPublicNumbers(E,N).public_key().recover_data_from_signature(data,padding=PKCS1v15(),algorithm=None)
except:
    print("The certificate couldn't be decrypted:")
    print("It could be that the algorithm use for decryption is different (not nav3 or similar), the dct/mct file is meant to be used with a patched navcore or the dct/mct file is fake")
    exit()

vMD5=path.split(path.splitext(fn)[0])[1].encode("utf-8")

nID=int.from_bytes(CERT[:0x04],byteorder="little")#get type of certificate describe if it is tied to the machine or the SD card (an mct renamed as dct behave like a mct because of that)
if nID&0x02:
    if MachineID=="":
        print("Variable MachineID is not set")
        exit()
    vMD5+=MachineID.encode("utf-8")
else:
    if nID&0x04:
        if MediaID=="":
            print("Variable MediaID is not set")
            exit()
        try:
            bytes.fromhex(MediaID)
        except:
            print("Variable MediaID is not hexadecimal (non hexadecimal value)")
            exit()
        if len(MediaID)%2:
            print("Variable MediaID is not hexadecimal (number of characters not even)")
            exit()
        if len(MediaID)<30 or len(MediaID)>32:
            print("Variable MediaID have a wrong size")
        b=bytes.fromhex(MediaID)
        c=(crc7(b[:15])<<1)+1
        if len(b)==15:
            print("CRC seems not to be present:")
            print("Correct MediaID should be "+MediaID+int.to_bytes(c).hex())
            b=b+int.to_bytes(c)
        else:
            if c!=b[15]:
                print("CRC seems incorrect:")
                print("Correct MediaID should be "+MediaID[:30]+int.to_bytes(c).hex())
                b=b[:15]+int.to_bytes(c)
        vMD5+=b
    else:
        if DeviceID=="":
            print("Variable DeviceID is not set, attempting to compute DeviceID with MachineID")
            if MachineID=="":
                print("Variable MachineID is not set")
                exit()
            a=MachineID.encode("utf-8")
            if len(a)<5:
                a+=b"*"*(5-len(a))
            if len(a)>5:
                #they screw up the algorithm so here is an equivalent and simpler one
                a=bytes([2,a[0]^a[-4],a[1]^a[-3],a[2]^a[-2],a[3]^a[-1]])
            cs=1
            for i in range(5):
                cs+=a[i]
            cs=cs&0xff
            a+=int.to_bytes(cs)
            a=int.from_bytes(a,byteorder="big")
            for _ in range(10):
                b=(a>>(3+8*5))&0x1f
                a=a<<5
                DeviceID+=BASE32t[b]
            print("DeviceID should be",DeviceID)
        else:
            DeviceID=DeviceID.upper().replace(" ","")
            a=0
            for c in DeviceID:
                if c not in BASE32t:
                    print("DeviceID",DeviceID,"is incorrect:",c,"is not part of base32 encoding chars")
                    exit()
                a=(a<<5)|(BASE32t.find(c))
            a=a>>2
            cs=a^0xff
            b=1
            for _ in range(5):
                a=a>>8
                b+=a&0xff
            b=b&0xff
            if b!=cs:
                print("Checksum in DeviceID is incorrect: got",hex(b),"but",hex(cs),"was expected")
                exit()
        vMD5+=DeviceID.encode("utf-8")

digest=Hash(MD5())
digest.update(vMD5)
d1=digest.finalize()
BK=bytes(a ^ b for a, b in zip(d1, CERT[0x04:0x14]))#bitwise xor to get the blowfish key

digest=Hash(MD5())
digest.update(BK)
d2=digest.finalize()
print(CERT)
if d2!=CERT[0x14:0x24]:#checksum to validate that the key is ok
    print("Hash doesn't match checksum:")
    print("The ID used for decryption as a wrong value or the mct/dct file was renamed")
    print("MD5 result:")
    print(d2)
    print("Value expected:")
    print(CERT[0x14:0x24])
    exit()
else:
    print("\nBlowfish/meta key:")
    print(" ".join([BK.hex().upper()[i:i+2] for i in range(0, len(BK)*2,2)]),path.split(path.splitext(fn)[0])[1],";")
