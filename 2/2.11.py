#!/usr/bin/env python3

import cryptolib

def mystery(M0):
    global ecb  # to check the result
    Key = cryptolib.randbin(16)
    Pref = cryptolib.randbin(cryptolib.randint(5,10))
    Suff = cryptolib.randbin(cryptolib.randint(5,10))
    M = cryptolib.PKCS7_pad(Pref+M0+Suff,16)
    ecb = (cryptolib.randint(0,1)==0)
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
    assert len(C)%BS==0
    cnt = len(set(C[i:i+BS] for i in range(0,len(C),BS)))
    return cnt<len(C)//BS

if __name__=='__main__':
    it = 1<<15
    prompt = 'Detection tests...'
    for i in range(it):
        if i%(1<<10)==0:
            print(prompt, f'{i+1:5d}/{it}', end='\r')
        res = is_ECB(mystery)
        assert res==ecb
    print(prompt, f'{it}/{it}')
