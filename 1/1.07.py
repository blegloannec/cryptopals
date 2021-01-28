#!/usr/bin/env python3

import base64, cryptolib

K = b'YELLOW SUBMARINE'

F = open('data/7.txt', 'r')
I = base64.b64decode(F.read())
F.close()

O = cryptolib.AES_ECB_decrypt(K, I)
print(O.decode())
