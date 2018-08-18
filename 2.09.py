#!/usr/bin/env python3

import cryptolib

M = b'YELLOW SUBMARINE'
print(cryptolib.PKCS7_pad(M,20))
