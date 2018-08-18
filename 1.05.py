#!/usr/bin/env python3

import base64, cryptolib

M = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
K = b"ICE"

O = base64.b16encode(cryptolib.bxor_repeat(M,K))
print(O.decode().lower())
