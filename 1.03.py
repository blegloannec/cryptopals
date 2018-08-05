#!/usr/bin/env python3

import base64

I = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
I = base64.b16decode(I.upper())

Alpha = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '")

for k in range(1,256):
    O = bytes(k^i for i in I)
    if all(chr(c) in Alpha for c in O):
        print(O.decode())
