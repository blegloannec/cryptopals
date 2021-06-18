#!/usr/bin/env python3

# identical to 4.29 but for md4

import md4
import os

def MAC(key: bytes, mess: bytes) -> bytes:
    return md4.md4(key + mess)

MESS = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
KSIZ = 16
_KEY = os.urandom(KSIZ)  # SECRET
MAC0 = MAC(_KEY, MESS)
SUFF = b';admin=true'

if __name__=='__main__':
    M = bytearray(KSIZ)  # 0-block for the unknown key
    M.extend(MESS)
    md4.pad(M)
    lold = len(M)
    # new message
    M.extend(SUFF)
    MESS1 = bytes(M[KSIZ:])
    print(MESS1)
    # forge a MAC
    md4.pad(M)
    MAC1 = md4.md4(M[lold:], MAC0, False)
    print(MAC1.hex())
    # check MAC validity
    assert MAC1 == MAC(_KEY, MESS1)
