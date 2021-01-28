#!/usr/bin/env python3

import cryptolib

A = '1c0111001f010100061a024b53535009181c'
B = '686974207468652062756c6c277320657965'

A = bytes.fromhex(A)
B = bytes.fromhex(B)

O = cryptolib.bxor(A,B)
print(O.hex())
