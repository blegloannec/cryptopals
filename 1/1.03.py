#!/usr/bin/env python3

import cryptolib

I = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
I = bytes.fromhex(I)

for k in range(1, 256):
    O = cryptolib.bxor_repeat(I, bytes([k]))
    if all(chr(c) in cryptolib.Alphanum for c in O):
        print(O.decode())
