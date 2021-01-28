#!/usr/bin/env python3

import cryptolib

def detect_single_byte_xor(I):
    for k in range(1, 256):
        O = cryptolib.bxor_repeat(I, bytes([k]))
        if all(chr(c) in cryptolib.Alphanum for c in O):
            return O
    return None

if __name__=='__main__':
    F = open('data/4.txt','r')
    for L in F.readlines():
        I = bytes.fromhex(L.strip())
        O = detect_single_byte_xor(I)
        if O is not None:
            print(L, end='')
            print(O.decode(), end='')
    F.close()
