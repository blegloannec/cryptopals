#!/usr/bin/env python3

import base64

M = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
K = b"ICE"

def xor_encrypt(M,K):
    return bytes(M[i]^K[i%len(K)] for i in range(len(M)))

O = base64.b16encode(xor_encrypt(M,K))
print(O.decode().lower())
