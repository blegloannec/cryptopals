#!/usr/bin/env python3

import base64, cryptolib

K = b'YELLOW SUBMARINE'

with open('data/7.txt', 'r') as F:
    I = base64.b64decode(F.read())

O = cryptolib.AES_ECB_decrypt(K, I)
print(O.decode())
