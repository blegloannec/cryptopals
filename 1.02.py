#!/usr/bin/env python3

import base64, cryptolib

A = '1c0111001f010100061a024b53535009181c'
B = '686974207468652062756c6c277320657965'

A = base64.b16decode(A.upper())
B = base64.b16decode(B.upper())

O = base64.b16encode(cryptolib.bxor(A,B))
print(O.decode().lower())
