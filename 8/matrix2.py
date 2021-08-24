#!/usr/bin/env python3

import poly2
import random
random.seed()
import time

N = poly2._K


## === Vectors and matrices in GF(2)^k === ##
# vectors (v) are represented by integers
# matrices are represented by list of cols (mc)
# or rows (mr)

def _cnt1s(x):
    o = 0
    while x:
        o += 1
        x &= x-1
    return o

def dot(x,y):
    return _cnt1s(x&y)&1

def rv_mul(M, v):
    p = 0
    for i,l in enumerate(M):
        p |= dot(l,v)<<i
    return p

def cv_mul(M, v):
    n = len(M)
    p = 0
    for i in range(n):
        for k in range(n):
            p ^= ((M[k]>>i) & (v>>k) & 1) << i
    return p

def rcc_mul(A, B):
    return [rv_mul(A, b) for b in B]

def swap(M):
    # swap between rows/cols form
    n = len(M)
    T = [0]*n
    for j in range(n):
        for i in range(n):
            if M[j]&(1<<i):
                T[i] |= 1<<j
    return T


# Sanity check
def _sanity_check(it=150):
    # squaring operator matrix
    Sc = [poly2.pmodmul(1<<i, 1<<i) for i in range(N)]

    k = 20  # for iterated squaring p -> p^(2^k) operator
    Mc = Sc
    Mr = swap(Mc)
    for _ in range(k-1):
        Mc = rcc_mul(Mr, Sc)
        Mr = swap(Mc)

    t0 = time.time()
    X = []
    for _ in range(it):
        x = random.randint(0, (1<<N)-1)
        #z = poly2.pmodmul(x, x)
        z = poly2.pmodexp(x, 1<<k)
        X.append((x, z))
    dt = time.time()-t0
    print(f'poly exp     {dt:.3f} s')

    t0 = time.time()
    for x,z in X:
        y = cv_mul(Mc, x)
        assert y == z
    dt = time.time()-t0
    print(f'col mat mul  {dt:.3f} s')

    t0 = time.time()
    for x,z in X:
        y = rv_mul(Mr, x)
        assert y == z
    dt = time.time()-t0
    print(f'row mat mul  {dt:.3f} s')

if __name__=='__main__':
    _sanity_check()
