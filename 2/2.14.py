#!/usr/bin/env python3

import base64, cryptolib

## SECRET DATA
_BS = 16
MysteryKey = cryptolib.randbin(_BS)
MysterySuff = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
MysteryPref = cryptolib.randbin(cryptolib.randint(1, 150))
##

def mystery(M0: bytes) -> bytes:
    M = cryptolib.pad(MysteryPref+M0+MysterySuff, _BS)
    C = cryptolib.AES_ECB_encrypt(MysteryKey, M)
    return C

def is_ECB(F, BS=16):  # from 2.12
    M = bytes(3*BS)
    C = mystery(M)
    assert len(C)%BS==0
    cnt = len(set(C[i:i+BS] for i in range(0, len(C), BS)))
    return cnt<len(C)//BS

def guess_block_size(F):  # from 2.12
    # the size if the ciphertext increases by one block exactly
    # when the size of the plaintext reaches a multiple of BS
    s0 = len(F(bytes(0)))
    n = 1
    while True:
        s = len(F(bytes(n)))
        if s>s0:
            return (s-s0, n)
        n += 1

def guess_pref_suff_size(F):
    # Illustration with BS = 4:
    # |PPPP|PP**|****|..|****|*SSS|SSSS|SSSS|
    # P the prefix part, * the injected part, S the suffix part
    #          off
    #         <-->
    # |PPPP|PP**|*SSS|SSSS|SSSS|
    BS, off = guess_block_size(F)
    assert is_ECB(F, BS)
    # Let us inject a certain number of separator blocks
    # to find the middle separation
    off += BS  # we add 1 block to off to make sure the prefix and suffix
               # are not "glued" in the same block
    sep = cryptolib.randbin(BS)  # random separator block
    rep = 5                      # repeats of sep, large enough
    while sep[0]==0 or sep[-1]==0:
        # we will inject l*0 + rep*sep + (off-l)*0,
        # we need to make sure that sep does not start of end by 0
        # to avoid an incorrect l to be accepted
        sep = cryptolib.randbin(BS)
    for l in range(off+1):
        #           <--rep*sep--->
        # |PPPP|PP00|****|..|****|0SSS|SSSS|SSSS|
        ciph = mystery(bytes(l) + rep*sep + bytes(off-l))
        for i in range(0, len(ciph), BS):
            if ciph[i:i+rep*BS] == rep*ciph[i:i+BS]:
                pref_size = i-l
                suff_size = len(F(bytes(off)))-BS - off - pref_size
                return (BS, pref_size, suff_size)

def guess_ecb_suffix(F0) -> bytes:  # modified from 2.12
    BS, pref_size, suff_size = guess_pref_suff_size(mystery)
    assert pref_size == len(MysteryPref)  # sanity check
    assert suff_size == len(MysterySuff)  # sanity check
    Suff = bytearray(BS-1)
    loff = (-pref_size)%BS
    F = lambda M: F0(bytes(loff)+M)[pref_size+loff:]
    for i in range(suff_size):
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
    assert GuessedSuff == MysterySuff
    print(GuessedSuff.decode(), end='')
