#!/usr/bin/env python3

import cryptolib

M = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
K = b"ICE"

O = cryptolib.bxor_repeat(M, K)
print(O.hex())
