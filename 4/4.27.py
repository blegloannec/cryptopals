#!/usr/bin/env python3

# the base code for this is from 2.16

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.strxor import strxor

BS  = 16

## SECRET DATA
PREF = b'comment1=cooking%20MCs;userdata='
SUFF = b';comment2=%20like%20a%20pound%20of%20bacon'
_KEY = get_random_bytes(BS)
##

def encrypt(userdata: str) -> bytes:
    userdata = userdata.replace(';','";"').replace('=','"="').encode()
    data = PREF + userdata + SUFF
    # IV = key
    return AES.new(_KEY, AES.MODE_CBC, iv=_KEY).encrypt(pad(data, BS))

def decrypt(ciph: bytes) -> bool:
    data = unpad(AES.new(_KEY, AES.MODE_CBC, iv=_KEY).decrypt(ciph), BS)
    if not all(32<=b<127 for b in data):
        raise ValueError('Invalid charset', data)
    return True

if __name__=='__main__':
    ciph0 = encrypt('*'*BS)
    assert decrypt(ciph0)
    # we prepend the first block + a block of 0s
    ciph1 = ciph0[:BS] + bytes(BS) + ciph0
    # plaintext:          m0, m1, ...
    # ciphertext: c0, zz, c0, c1, ...
    # decrypted:  d0, d1, d2, d3, ...
    # we have d0 = m0 and d2 = zz ⊕ AES_decrypt(c0) = IV ⊕ m0
    # hence d0 ⊕ d2 = IV
    key = None
    try:
        decrypt(ciph1)
    except ValueError as err:
        err_msg, deciph1 = err.args
        print(err_msg, deciph1)
        key = strxor(deciph1[:BS], deciph1[2*BS:3*BS])
    assert key == _KEY
    print()
    print(unpad(AES.new(key, AES.MODE_CBC, iv=key).decrypt(ciph0), BS).decode())
