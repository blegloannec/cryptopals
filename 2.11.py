#!/usr/bin/env python3

import cryptolib, random
random.seed()

def mystery(M0):
    global ecb  # to check the result
    Key = cryptolib.randbin(16)
    Pref = cryptolib.randbin(random.randint(5,10))
    Suff = cryptolib.randbin(random.randint(5,10))
    M = cryptolib.PKCS7_pad(Pref+M0+Suff,16)
    ecb = (random.randint(0,1)==0)
    if ecb:
        C = cryptolib.AES_ECB_encrypt(Key,M)
    else:
        IV = cryptolib.randbin(16)
        C = cryptolib.AES_CBC_encrypt(Key,IV,M)
    return C

# chosen-plaintext attack
def is_ECB(F, BS=16):
    M = bytes(3*BS)
    C = mystery(M)
    assert(len(C)%BS==0)
    cnt = len(set(C[i:i+BS] for i in range(0,len(C),BS)))
    return cnt<len(C)//BS

def main():
    for _ in range(1<<15):
        res = is_ECB(mystery)
        assert(res==ecb)

main()
