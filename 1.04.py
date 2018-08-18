#!/usr/bin/env python3

import sys, base64, cryptolib

def test(I16):
    I = base64.b16decode(I16.upper())
    for k in range(1,256):
        O = cryptolib.bxor_repeat(I,bytes([k]))
        if all(chr(c) in cryptolib.Alphanum for c in O):
            print(I16)
            print(O.decode())

F = open('4.txt','r')
for I in F.readlines():
    test(I.strip())
F.close()
