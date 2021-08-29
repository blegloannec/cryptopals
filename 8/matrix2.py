#!/usr/bin/env python3

## === Vectors and matrices in GF(2)^k === ##
# vectors (v) are represented by integers
# matrices (m) are represented by lists of cols (c) or rows (r)
# m_swap() swaps between representations
# since: rows repr. = columns repr. of the transpose
# then m_swap is also the transpose operation

def _cnt1s(x):
    o = 0
    while x:
        o += 1
        x &= x-1
    return o

def v_dot(x,y):
    return _cnt1s(x&y)&1

def rv_mul(M, v):
    p = 0
    for i,l in enumerate(M):
        p |= v_dot(l,v)<<i
    return p

def cv_mul(M, v):
    n = len(M)
    p = 0
    for i in range(n):
        for k in range(n):
            p ^= ((M[k]>>i) & (v>>k) & 1) << i
    return p

def m_add(A, B): # works for both forms
    return [a^b for a,b in zip(A,B)]

def rcc_mul(A, B):
    return [rv_mul(A, b) for b in B]

def m_swap(M, m=None):
    # swap between rows/cols form
    n = len(M)
    if m is None:
        m = n
    T = [0]*m
    for j in range(n):
        for i in range(m):
            if M[j]&(1<<i):
                T[i] |= 1<<j
    return T

def m_id(n):
    return [1<<i for i in range(n)]

def m_gauss(M):
    M = M.copy()
    n = len(M)
    I = m_id(n)
    for j in range(n):
        i0 = -1
        for i in range(j, n):
            if (M[i]>>j)&1:
                i0 = i
                break
        if i0 < 0:
            continue
        M[j],M[i0] = M[i0],M[j]
        I[j],I[i0] = I[i0],I[j]
        for i in range(j+1, n):
            if (M[i]>>j)&1:
                M[i] ^= M[j]
                I[i] ^= I[j]
    return M,I

def r_nullspace(M, m=None):
    T,B = m_gauss(m_swap(M, m))
    return [b for r,b in zip(T,B) if r==0]

def r_print(M, m=None):
    n = len(M)
    if m is None:
        m = n
    line = f'{{:0{m}b}}'
    for r in M:
        print(line.format(r)[::-1])


## Sanity checks
def _sanity_check1(it=100):
    # squaring operator matrix
    Sc = [poly2.pmodmul(1<<i, 1<<i) for i in range(N)]

    k = 20  # for iterated squaring p -> p^(2^k) operator
    Mc = Sc
    Mr = m_swap(Mc)
    for _ in range(k-1):
        Mc = rcc_mul(Mr, Sc)
        Mr = m_swap(Mc)

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

def _sanity_check2(it=100):
    for _ in range(it):
        n = random.randint(1,100)
        m = random.randint(1,100)
        M = [random.randint(0, (1<<m)-1) for _ in range(n)]
        N = r_nullspace(M, m)
        for v in N:
            assert rv_mul(M, v) == 0

if __name__=='__main__':
    import random, time, poly2
    random.seed()
    N = poly2._K
    _sanity_check1()
    _sanity_check2()
