#!/usr/bin/env python3

import cryptolib

BS = 16

for M in [b'ICE ICE BABY\x04\x04\x04\x04',
          b'ICE ICE BABY\x05\x05\x05\x05',
          b'ICE ICE BABY\x01\x02\x03\x04']:
    try:
        print(cryptolib.PKCS7_unpad(M,BS))
    except cryptolib.InvalidPadding as E:
        print(E)
