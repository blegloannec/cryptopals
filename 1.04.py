#!/usr/bin/env python3

import sys, base64

Alpha = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '\n\r\t")

def test(I16):
    I = base64.b16decode(I16.upper())
    for k in range(1,256):
        O = bytes(k^i for i in I)
        if all(chr(c) in Alpha for c in O):
            print(I16)
            print(O)

F = open('4.txt','r')
for I in F.readlines():
    test(I.strip())
F.close()
