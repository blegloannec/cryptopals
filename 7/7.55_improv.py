#!/usr/bin/env pypy3

import md4
from md4 import msk32, lrot, rrot, F
import os

# Exact same attack technique as 7.55.py except we implement
# the better differential/modification from:
# Sasaki et al., New Message Difference for MD4, 2007
# https://www.iacr.org/archive/fse2007/45930331/45930331.pdf

def differential(M):
    #assert len(M) == 16
    Md = M.copy()
    Md[0]  = (Md[0]  + (1<<28)) & msk32
    Md[2]  = (Md[2]  + (1<<31)) & msk32
    Md[4]  = (Md[4]  + (1<<31)) & msk32
    Md[8]  = (Md[8]  + (1<<31)) & msk32
    Md[12] = (Md[12] + (1<<31)) & msk32
    return Md

def modification(M):
    # M is a block (list of 16 int32)
    # Block modifications to enforce rules from Table 8
    # resulting block should work with proba. 2^(-10)
    eq  = lambda x,y,k: (x^y)&(1<<k)
    eq0 = lambda x,k: x&(1<<k)
    eq1 = lambda x,k: (x&(1<<k))^(1<<k)    
    a,b,c,d = md4.H0

    # Rules of the first 16 steps (first pass on the message)
    a0 = a
    a = lrot((a + F(b,c,d) + M[0]) & msk32, 3)
    a ^= eq1(a,0)|eq0(a,1)|eq(a,b,7)|eq(a,b,9)|eq(a,b,31)
    M[0] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[1]) & msk32, 7)
    d ^= eq1(d,0)|eq0(d,1)|eq0(d,7)|eq1(d,9)|eq(d,a,11)|eq0(d,19)|eq1(d,31)
    M[1] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[2]) & msk32, 11)
    c ^= eq0(c,0)|eq1(c,1)|eq0(c,7)|eq0(c,9)|eq1(c,11)|eq1(c,19)|eq(c,d,20)|eq(c,d,21)|eq0(c,24)|eq1(c,31)
    M[2] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[3]) & msk32, 19)
    b ^= eq(b,c,3)|eq(b,c,4)|eq(b,c,5)|eq(b,c,6)|eq1(b,7)|eq(b,c,8)|eq1(b,9)|eq0(b,11)|eq0(b,19)|eq0(b,20)|eq1(b,21)|eq(b,c,22)|eq(b,c,23)|eq1(b,24)|eq1(b,31)
    M[3] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32

    a0 = a
    a = lrot((a + F(b,c,d) + M[4]) & msk32, 3)
    a ^= eq1(a,3)|eq1(a,4)|eq1(a,5)|eq1(a,6)|eq1(a,7)|eq1(a,8)|eq0(a,9)|eq0(a,11)|eq(a,b,18)|eq0(a,19)|eq0(a,20)|eq0(a,21)|eq1(a,22)|eq1(a,23)|eq0(a,24)|eq(a,b,31)
    M[4] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[5]) & msk32, 7)
    d ^= eq(d,a,1)|eq(d,a,2)|eq0(d,3)|eq0(d,4)|eq0(d,5)|eq0(d,6)|eq0(d,7)|eq0(d,8)|eq0(d,9)|eq0(d,18)|eq0(d,19)|eq1(d,20)|eq1(d,21)|eq1(d,22)|eq1(d,23)|eq1(d,24)|eq0(d,31)
    M[5] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[6]) & msk32, 11)
    c ^= eq1(c,1)|eq1(c,2)|eq1(c,3)|eq1(c,4)|eq1(c,5)|eq1(c,6)|eq1(c,7)|eq1(c,8)|eq0(c,9)|eq0(c,18)|eq1(c,19)|eq0(c,20)|eq0(c,22)|eq0(c,23)|eq1(c,24)|eq1(c,25)|eq0(c,31)
    M[6] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[7]) & msk32, 19)
    b ^= eq0(b,1)|eq0(b,2)|eq1(b,3)|eq0(b,4)|eq0(b,5)|eq0(b,6)|eq0(b,7)|eq0(b,8)|eq0(b,9)|eq0(b,12)|eq1(b,18)|eq0(b,19)|eq1(b,20)|eq0(b,22)|eq0(b,23)|eq0(b,24)|eq(b,c,25)|eq1(b,31)
    M[7] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32

    a0 = a
    a = lrot((a + F(b,c,d) + M[8]) & msk32, 3)
    a ^= eq1(a,1)|eq1(a,2)|eq1(a,3)|eq1(a,4)|eq0(a,5)|eq1(a,6)|eq1(a,7)|eq1(a,8)|eq1(a,9)|eq(a,b,12)|eq1(a,22)|eq0(a,23)|eq1(a,24)|eq0(a,25)|eq(a,b,26)|eq(a,b,27)|eq(a,b,29)|eq(a,b,30)|eq0(a,31)
    M[8] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[9]) & msk32, 7)
    d ^= eq1(d,12)|eq1(d,22)|eq1(d,23)|eq0(d,25)|eq0(d,26)|eq1(d,27)|eq1(d,29)|eq1(d,30)|eq0(d,31)
    M[9] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[10]) & msk32, 11)
    c ^= eq0(c,12)|eq1(c,22)|eq1(c,23)|eq0(c,25)|eq1(c,26)|eq1(c,27)|eq0(c,29)|eq0(c,30)|eq0(c,31)
    M[10] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[11]) & msk32, 19)
    b ^= eq1(b,12)|eq1(b,25)|eq0(b,26)|eq0(b,27)|eq(b,c,28)|eq1(b,29)|eq1(b,30)|eq0(b,31)
    M[11] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32

    a0 = a
    a = lrot((a + F(b,c,d) + M[12]) & msk32, 3)
    a ^= eq0(a,12)|eq0(a,25)|eq0(a,28)|eq1(a,29)
    M[12] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[13]) & msk32, 7)
    d ^= eq0(d,12)|eq0(d,25)|eq0(d,28)|eq0(d,29)
    M[13] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[14]) & msk32, 11)
    c ^= eq1(c,25)|eq1(c,28)|eq1(c,29)|eq(c,d,31)
    M[14] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[15]) & msk32, 19)
    b ^= eq(b,c,28)|eq1(b,31)
    M[15] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32


if __name__=='__main__':
    a0,b0,c0,d0 = md4.H0
    cnt = 1
    while True:
        M = md4.bytes_to_ints32(os.urandom(64))
        modification(M)
        Md = differential(M)
        if md4.compress(a0,b0,c0,d0, M) == md4.compress(a0,b0,c0,d0, Md):
            break
        cnt += 1
    M  = md4.ints32_to_bytes(M)
    Md = md4.ints32_to_bytes(Md)
    print(f'Collision found ({cnt} tries):')
    print(f'M  = {M.hex()}')
    print(f"M' = {Md.hex()}")
    H  = md4.md4(M)
    Hd = md4.md4(Md)
    assert H == Hd
    print(f'H  = {H.hex()}')
