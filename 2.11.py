#!/usr/bin/env python3

# chosen-plaintext attack

from Crypto.Cipher import AES
import random
random.seed()

def randbin(S):
    return bytes(random.randint(0,255) for _ in range(S))

def PKCS7(BS,M):
    assert(BS<=256)
    r = len(M)%BS
    if r>0:
        M += bytes([BS-r]*(BS-r))
    return M

def mystery(M0):
    global ecb  # to check the result
    Key = randbin(16)
    Pref = randbin(random.randint(5,10))
    Suff = randbin(random.randint(5,10))
    M = PKCS7(16,Pref+M0+Suff)
    ecb = (random.randint(0,1)==0)
    if ecb:
        Ciph = AES.new(Key,AES.MODE_ECB)
        C = Ciph.encrypt(M)
    else:
        IV = randbin(16)
        Ciph = AES.new(Key,AES.MODE_CBC,IV)
        C = Ciph.encrypt(M)
    return C

def is_ECB(F):
    BS = 16
    M = b'\x00'*(3*BS)
    C = mystery(M)
    assert(len(C)%BS==0)
    cnt = len(set(C[i:i+BS] for i in range(0,len(C),BS)))
    return cnt<len(C)//BS

def main():
    for _ in range(1<<15):
        res = is_ECB(mystery)
        assert(res==ecb)

main()
