#!/usr/bin/env python3

import base64
from Crypto.Cipher import AES

K = b'YELLOW SUBMARINE'

F = open('7.txt','r')
I = base64.b64decode(F.read())
F.close()

C = AES.new(K,AES.MODE_ECB)
O = C.decrypt(I)
print(O.decode())
