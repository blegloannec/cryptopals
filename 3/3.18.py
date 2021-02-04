#!/usr/bin/env python3

import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

BS = 16

ciph = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
key = b'YELLOW SUBMARINE'
nonce = (0).to_bytes(BS//2, 'little')

def AES_CTR(key: bytes, nonce: bytes, msg: bytes) -> bytes:
    encrypt = AES.new(key, AES.MODE_ECB).encrypt
    ciph = []
    cnt = 0
    for b in range(0, len(msg), BS):
        stream = encrypt(nonce + cnt.to_bytes(BS//2, 'little'))
        block = msg[b:b+BS]
        if len(block) < BS:
            stream = stream[:len(block)]
        ciph.append(strxor(block, stream))
        cnt += 1
    return b''.join(ciph)

print(AES_CTR(key, nonce, ciph))


# and using Cryptodome (requires a custom counter)
from Cryptodome.Util import Counter
ctr = Counter.new(8*BS//2, prefix=nonce, initial_value=0, little_endian=True)
print(AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ciph))
