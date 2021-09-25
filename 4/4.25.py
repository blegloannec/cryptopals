#!/usr/bin/env python3

import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from Cryptodome.Util.Padding import unpad
from Cryptodome.Random import get_random_bytes

BS = 16

## SECRET DATA
# retrieve data from 1.07 (also /1/data/7.txt)
with open('data/25.txt', 'rb') as F:
    DATA = base64.b64decode(F.read())
DATA = unpad(AES.new(b'YELLOW SUBMARINE', AES.MODE_ECB).decrypt(DATA), BS)
_KEY = get_random_bytes(BS)
_NONCE = get_random_bytes(BS//2)
ctr = lambda idx: Counter.new(8*BS//2, prefix=_NONCE, initial_value=idx)
##
DATA = bytearray(AES.new(_KEY, AES.MODE_CTR, counter=ctr(0)).encrypt(DATA))


# exposed function (implemented for one byte)
def edit_byte(offset: int, new_byte: int):
    b, i = divmod(offset, BS)
    ciph0 = DATA[b*BS:(b+1)*BS]
    mess = bytearray(AES.new(_KEY, AES.MODE_CTR, counter=ctr(b)).decrypt(ciph0))
    mess[i] = new_byte
    ciph1 = AES.new(_KEY, AES.MODE_CTR, counter=ctr(b)).encrypt(mess)
    DATA[offset] = ciph1[i]

def retrieve_byte(i):  # attack
    c = DATA[i]
    for b in range(256):
        edit_byte(i, b)
        if DATA[i] == c:
            return b


## faster approach to retrieve everything
# more convenient exposed primitive
def edit_all(new_text: bytes):
    global DATA
    assert len(new_text) == len(DATA)
    DATA = AES.new(_KEY, AES.MODE_CTR, counter=ctr(0)).encrypt(new_text)

def retrieve_all():  # attack
    ciph = DATA.copy()
    deciph = bytearray(ciph)
    for b in range(256):
        edit_all(bytes([b]*len(ciph)))
        for i in range(len(ciph)):
            if DATA[i] == ciph[i]:
                deciph[i] = b
    return deciph


if __name__=='__main__':
    #deciph = bytes(retrieve_byte(i) for i in range(len(DATA)))
    deciph = retrieve_all()
    print(deciph.decode())
