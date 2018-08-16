#!/usr/bin/env python3

from Crypto.Cipher import AES
import random, base64
random.seed()

def randbin(S):
    return bytes(random.randint(0,255) for _ in range(S))

def PKCS7(BS,M):
    assert(BS<=256)
    r = len(M)%BS
    if r>0:
        M += bytes([BS-r]*(BS-r))
    return M

MysteryKey = randbin(16)
MysterySuff = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def mystery(M0):
    M = PKCS7(16,M0+MysterySuff)
    Ciph = AES.new(MysteryKey,AES.MODE_ECB)
    C = Ciph.encrypt(M)
    return C

def is_ECB(BS,F):
    M = bytes(3*BS)
    C = mystery(M)
    assert(len(C)%BS==0)
    cnt = len(set(C[i:i+BS] for i in range(0,len(C),BS)))
    return cnt<len(C)//BS

def guess_block_size(F):
    s = None
    n = 1
    while True:
        s0,s = s,len(F(bytes(n)))
        if s0 is not None and s-s0>0:
            return s-s0,n-1
        n += 1

def guess_ecb_suffix(F):
    BS,off = guess_block_size(F)
    assert(is_ECB(BS,F))
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
        assert(c<256)
        Suff.append(c)
    return bytes(Suff[BS-1:])

GuessedSuff = guess_ecb_suffix(mystery)
assert(GuessedSuff==MysterySuff)
print(GuessedSuff.decode())
