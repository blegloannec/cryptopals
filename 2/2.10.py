#!/usr/bin/env python3

import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

def CBC_encrypt(BS, Encrypt, Combine, M, IV):
    C = [IV]
    for i in range(0, len(M), BS):
        C.append(Encrypt(Combine(M[i:i+BS], C[-1])))
    return b''.join(C[1:])

def CBC_decrypt(BS, Decrypt, Combine, C, IV):
    C = [IV] + [C[i:i+BS] for i in range(0, len(C), BS)]
    M = []
    for i in range(1, len(C)):
        M.append(Combine(Decrypt(C[i]), C[i-1]))
    return b''.join(M)

def main():
    BS = 16
    IV = b'\x00'*BS
    K = b'YELLOW SUBMARINE'
    AESCrypt = AES.new(K, AES.MODE_ECB)
    with open('data/10.txt', 'r') as F:
        I = base64.b64decode(F.read())
    O = CBC_decrypt(BS, AESCrypt.decrypt, strxor, I, IV)
    print(O.decode())
    assert CBC_encrypt(BS, AESCrypt.encrypt, strxor, O, IV) == I

main()
