#!/usr/bin/env python3

import base64, cryptolib

MysteryKey = cryptolib.randbin(16)
MysterySuff = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def mystery(M0):
    M = cryptolib.PKCS7_pad(M0+MysterySuff, 16)
    C = cryptolib.AES_ECB_encrypt(MysteryKey, M)
    return C

def is_ECB(F, BS=16):
    M = bytes(3*BS)
    C = mystery(M)
    assert len(C)%BS==0
    cnt = len(set(C[i:i+BS] for i in range(0, len(C), BS)))
    return cnt<len(C)//BS

def guess_block_size(F):
    # the size if the ciphertext increases by one block exactly
    # when the size of the plaintext reaches a multiple of BS
    s0 = len(F(bytes(0)))
    n = 1
    while True:
        s = len(F(bytes(n)))
        if s>s0:
            return (s-s0, n)
        n += 1

def guess_ecb_suffix(F):
    BS,off = guess_block_size(F)
    assert is_ECB(F,BS)
    SuffSize = len(F(b''))-off
    Suff = bytearray(BS-1)
    for i in range(SuffSize):
        q,r = divmod(i,BS)
        C = F(bytes(BS-1-r))[q*BS:(q+1)*BS]
        M = Suff[-BS+1:]
        c = 0
        M.append(c)
        while c<256 and F(bytes(M))[:BS]!=C:
            c += 1
            M[-1] = c
        assert c<256
        Suff.append(c)
    return bytes(Suff[BS-1:])

if __name__=='__main__':
    GuessedSuff = guess_ecb_suffix(mystery)
    assert GuessedSuff==MysterySuff
    print(GuessedSuff.decode(), end='')
