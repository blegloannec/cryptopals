#!/usr/bin/env pypy3

import md4
from md4 import msk32, lrot, rrot, F, G
import os

# Wang et al, Cryptanalysis of the Hash Functions MD4 and RIPEMD
# https://www.iacr.org/archive/eurocrypt2005/34940001/34940001.pdf

def differential(M):
    #assert len(M) == 16
    Md = M.copy()
    Md[1]  = (Md[1]  + (1<<31))           & msk32
    Md[2]  = (Md[2]  + (1<<31) - (1<<28)) & msk32
    Md[12] = (Md[12] - (1<<16))           & msk32
    return Md

def modification(M):
    # M is a block (list of 16 int32)
    # Block modifications to enforce rules from Table 6
    eq  = lambda x,y,k: (x^y)&(1<<k)
    eq0 = lambda x,k: x&(1<<k)
    eq1 = lambda x,k: (x&(1<<k))^(1<<k)    
    a,b,c,d = md4.H0
    A = [a]; D = [d]; C = [c]; B = [b]

    # 1. Rules of the first 16 steps (first pass on the message)
    a0 = a
    a = lrot((a + F(b,c,d) + M[0]) & msk32, 3)
    # Enforce (table 6, line 1): a1[6] == b0[6]
    # a1 := a1 ^ ((a1[6] ^ b0[6]) << 6)
    # m0 := (a1>>>3) - a0 - F(b0,c0,d0)
    a ^= eq(a,b,6)
    M[0] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[1]) & msk32, 7)
    # Enforce (table 6, line 2): d1[6] = 0, d1[7] = a1[7], d1[10] = a1[10]
    d ^= eq0(d,6) ^ eq(d,a,7) ^ eq(d,a,10)
    M[1] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[2]) & msk32, 11)
    # Enforce (table 6, line 3): c1[6] = 1, c1[7] = 1, c1[10] = 0, c1[25] = d1[25]
    c ^= eq1(c,6) ^ eq1(c,7) ^ eq0(c,10) ^ eq(c,d,25)
    M[2] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[3]) & msk32, 19)
    # Enforce (table 6, line 4): b1[6] = 1, b1[7] = 0, b1[10] = 0, b1[25] = 0
    b ^= eq1(b,6) ^ eq0(b,7) ^ eq0(b,10) ^ eq0(b,25)
    M[3] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32

    A.append(a); D.append(d); C.append(c); B.append(b)

    a0 = a
    a = lrot((a + F(b,c,d) + M[4]) & msk32, 3)
    a ^= eq1(a,7) ^ eq1(a,10) ^ eq0(a,25) ^ eq(a,b,13)
    M[4] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[5]) & msk32, 7)
    d ^= eq0(d,13) ^ eq(d,a,18) ^ eq(d,a,19) ^ eq(d,a,20) ^ eq(d,a,21) ^ eq1(d,25)
    M[5] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[6]) & msk32, 11)
    c ^= eq(c,d,12) ^ eq0(c,13) ^ eq(c,d,14) ^ eq0(c,18) ^ eq0(c,19) ^ eq1(c,20) ^ eq0(c,21)
    M[6] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[7]) & msk32, 19)
    b ^= eq1(b,12) ^ eq1(b,13) ^ eq0(b,14) ^ eq(b,c,16) ^ eq0(b,18) ^ eq0(b,19) ^ eq0(b,20) ^ eq0(b,21)
    M[7] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32

    A.append(a); D.append(d); C.append(c); B.append(b)

    a0 = a
    a = lrot((a + F(b,c,d) + M[8]) & msk32, 3)
    a ^= eq1(a,12) ^ eq1(a,13) ^ eq1(a,14) ^ eq0(a,16) ^ eq0(a,18) ^ eq0(a,19) ^ eq0(a,20) ^ eq(a,b,22) ^ eq1(a,21) ^ eq(a,b,25)
    M[8] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[9]) & msk32, 7)
    d ^= eq1(d,12) ^ eq1(d,13) ^ eq1(d,14) ^ eq0(d,16) ^ eq0(d,19) ^ eq1(d,20) ^ eq1(d,21) ^ eq0(d,22) ^ eq1(d,25) ^ eq(d,a,29)
    M[9] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[10]) & msk32, 11)
    c ^= eq1(c,16) ^ eq0(c,19) ^ eq0(c,20) ^ eq0(c,21) ^ eq0(c,22) ^ eq0(c,25) ^ eq1(c,29) ^ eq(c,d,31)
    M[10] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[11]) & msk32, 19)
    b ^= eq0(b,19) ^ eq1(b,20) ^ eq1(b,21) ^ eq(b,c,22) ^ eq1(b,25) ^ eq0(b,29) ^ eq0(b,31)
    M[11] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32

    A.append(a); D.append(d); C.append(c); B.append(b)

    a0 = a
    a = lrot((a + F(b,c,d) + M[12]) & msk32, 3)
    a ^= eq0(a,22) ^ eq0(a,25) ^ eq(a,b,26) ^ eq(a,b,28) ^ eq1(a,29) ^ eq0(a,31)
    M[12] = (rrot(a, 3) - a0 - F(b,c,d)) & msk32

    d0 = d
    d = lrot((d + F(a,b,c) + M[13]) & msk32, 7)
    d ^= eq0(d,22) ^ eq0(d,25) ^ eq1(d,26) ^ eq1(d,28) ^ eq0(d,29) ^ eq1(d,31)
    M[13] = (rrot(d, 7) - d0 - F(a,b,c)) & msk32

    c0 = c
    c = lrot((c + F(d,a,b) + M[14]) & msk32, 11)
    c ^= eq(c,d,18) ^ eq1(c,22) ^ eq1(c,25) ^ eq0(c,26) ^ eq0(c,28) ^ eq0(c,29)
    M[14] = (rrot(c, 11) - c0 - F(d,a,b)) & msk32

    b0 = b
    b = lrot((b + F(c,d,a) + M[15]) & msk32, 19)
    b ^= eq0(b,18) ^ eq1(b,25) ^ eq1(b,26) ^ eq1(b,28) ^ eq0(b,29)
    M[15] = (rrot(b, 19) - b0 - F(c,d,a)) & msk32

    A.append(a); D.append(d); C.append(c); B.append(b)

    # 2. Rules of the second pass on the message (lines from a5...)
    a0 = a
    a = lrot((a + G(b,c,d) + M[0] + 0x5a827999) & msk32, 3)
    a ^= eq(a,c,18) ^ eq1(a,25) ^ eq0(a,26) ^ eq1(a,28) ^ eq1(a,31)
    M[0] = (rrot(a,3) - a0 - G(b,c,d) - 0x5a827999) & msk32
    A[1] = lrot((A[0] + F(B[0],C[0],D[0]) + M[0]) & msk32, 3)
    M[1] = (rrot(D[1], 7)  - D[0] - F(A[1],B[0],C[0])) & msk32
    M[2] = (rrot(C[1], 11) - C[0] - F(D[1],A[1],B[0])) & msk32
    M[3] = (rrot(B[1], 19) - B[0] - F(C[1],D[1],A[1])) & msk32
    M[4] = (rrot(A[2], 3)  - A[1] - F(B[1],C[1],D[1])) & msk32

    d0 = d
    d = lrot((d + G(a,b,c) + M[4] + 0x5a827999) & msk32, 5)
    d ^= eq(d,a,18) ^ eq(d,b,25) ^ eq(d,b,26) ^ eq(d,b,28) ^ eq(d,b,31)
    M[4] = (rrot(d,5) - d0 - G(a,b,c) - 0x5a827999) & msk32
    A[2] = lrot((A[1] + F(B[1],C[1],D[1]) + M[4]) & msk32, 3)
    M[5] = (rrot(D[2], 7)  - D[1] - F(A[2],B[1],C[1])) & msk32
    M[6] = (rrot(C[2], 11) - C[1] - F(D[2],A[2],B[1])) & msk32
    M[7] = (rrot(B[2], 19) - B[1] - F(C[2],D[2],A[2])) & msk32
    M[8] = (rrot(A[3], 3)  - A[2] - F(B[2],C[2],D[2])) & msk32


if __name__=='__main__':
    a0,b0,c0,d0 = md4.H0
    cnt = 1
    while True:
        M = md4.bytes_to_ints32(os.urandom(64))
        modification(M)  # should work with proba. ~2^(-16)
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
