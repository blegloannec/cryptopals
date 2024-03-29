#!/usr/bin/env python3

from collections import namedtuple
import random
random.seed()


## === Vectors and matrices in GF(2)^k === ##
# vectors  are represented by integers
# matrices are represented by lists:
#   of column vectors (CMatrix)
#   or row    vectors (RMatrix)
# swap() swaps between representations
# since: rows repr. = columns repr. of the transpose
# then swap is analog to the transpose operation
# except:
#   swap      swaps CMatrix/RMatrix but not r/c
#   transpose swaps r/c but keeps the type

RMatrix = namedtuple('RMatrix', ('r','c','M'))
CMatrix = namedtuple('CMatrix', ('r','c','M'))

def rmatrix(r: int, c: int, M=None) -> RMatrix:
    if M is None:
        M = [0]*r
    else:
        assert len(M) == r
    return RMatrix(r, c, M)

def cmatrix(r: int, c: int, M=None) -> CMatrix:
    if M is None:
        M = [0]*c
    else:
        assert len(M) == c
    return CMatrix(r, c, M)

def _id(n: int):
    return [1<<i for i in range(n)]

def r_id(n: int) -> RMatrix:
    return RMatrix(n, n, _id(n))

def c_id(n: int) -> CMatrix:
    return CMatrix(n, n, _id(n))

def r_print(M: RMatrix):
    assert isinstance(M, RMatrix)
    line = f'{{:0{M.c}b}}'
    for r in M.M:
        print(line.format(r)[::-1])


## Basic operations
def _cnt1s(x: int) -> int:
    o = 0
    while x:
        o += 1
        x &= x-1
    return o

def v_dot(x: int, y: int) -> int:
    return _cnt1s(x&y)&1

def r_add(A: RMatrix, B: RMatrix) -> RMatrix:
    assert isinstance(A, RMatrix) and isinstance(B, RMatrix)
    assert A.r == B.r and A.c == B.c
    return RMatrix(A.r, A.c, [a^b for a,b in zip(A.M,B.M)])

def c_add(A: CMatrix, B: CMatrix) -> CMatrix:  # actually the same
    assert isinstance(A, CMatrix) and isinstance(B, CMatrix)
    assert A.r == B.r and A.c == B.c
    return CMatrix(A.r, A.c, [a^b for a,b in zip(A.M,B.M)])

def rv_mul(M: RMatrix, v: int) -> int:  # fast
    assert isinstance(M, RMatrix)
    p = 0
    for i,l in enumerate(M.M):
        p |= v_dot(l,v)<<i
    return p

def cv_mul(M: CMatrix, v: int) -> int:  # slow
    assert isinstance(M, CMatrix)
    p = 0
    for i in range(M.r):
        for k in range(M.c):
            p ^= ((M.M[k]>>i) & (v>>k) & 1) << i
    return p

def rcc_mul(A: RMatrix, B: CMatrix) -> CMatrix:  # fast
    assert isinstance(A, RMatrix) and isinstance(B, CMatrix)
    assert A.c == B.r
    return CMatrix(A.r, B.c, [rv_mul(A, b) for b in B.M])


## Swap/Transpose primitives
def _swap(M, bl):
    T = [0]*bl
    for j in range(len(M)):
        for i in range(bl):
            if M[j]&(1<<i):
                T[i] |= 1<<j
    return T

def rc_swap(M: RMatrix) -> CMatrix:
    assert isinstance(M, RMatrix)
    return CMatrix(M.r, M.c, _swap(M.M, M.c))

def cr_swap(M: CMatrix) -> RMatrix:
    assert isinstance(M, CMatrix)
    return RMatrix(M.r, M.c, _swap(M.M, M.r))

def r_transpose(M: RMatrix) -> RMatrix:
    assert isinstance(M, RMatrix)
    return RMatrix(M.c, M.r, _swap(M.M, M.c))

def c_transpose(M: CMatrix) -> CMatrix:
    assert isinstance(M, CMatrix)
    return CMatrix(M.c, M.r, _swap(M.M, M.r))


## Additional convenient operations
def rcr_mul(A: RMatrix, B: CMatrix) -> RMatrix:
    return cr_swap(rcc_mul(A, B))

def ccc_mul(A: CMatrix, B: CMatrix) -> CMatrix:
    return rcc_mul(cr_swap(A), B)

def r_trunc(M: RMatrix, r: int) -> RMatrix:
    assert isinstance(M, RMatrix)
    assert r <= M.r
    return RMatrix(r, M.c, M.M[:r])

def r_extend(M: RMatrix, R) -> RMatrix:
    assert isinstance(M, RMatrix)
    return RMatrix(M.r+len(R), M.c, M.M+R)

def r_random(r: int, c: int) -> RMatrix:
    return RMatrix(r, c, [random.randint(0, (1<<c)-1) for _ in range(r)])


## Gaussian elimination
def r_gauss(M: RMatrix):
    assert isinstance(M, RMatrix)
    r,c,M = M
    rank = 0
    M = list(M)  # copy / tuple -> list
    I = _id(r)
    for j in range(c):
        i0 = -1
        for i in range(rank, r):
            if (M[i]>>j)&1:
                i0 = i
                break
        if i0 < 0:
            continue
        M[rank],M[i0] = M[i0],M[rank]
        I[rank],I[i0] = I[i0],I[rank]
        for i in range(rank+1, r):
            if (M[i]>>j)&1:
                M[i] ^= M[rank]
                I[i] ^= I[rank]
        rank += 1
    return (rank, RMatrix(r, c, M), RMatrix(r, r, I))

def r_nullspace(M: RMatrix):
    assert isinstance(M, RMatrix)
    rank,_,B = r_gauss(r_transpose(M))
    return B.M[rank:]

def _v_swap(b, i, j):
    bi = (b>>i)&1
    bj = (b>>j)&1
    return b if bi==bj else b^(1<<i)^(1<<j)

# particular solution to a system
def r_system_solve(M: RMatrix, b: int) -> int:
    assert isinstance(M, RMatrix)
    r,c,M = M
    rank = 0
    M = list(M)  # copy / tuple -> list
    for j in range(c):
        i0 = -1
        for i in range(rank, r):
            if (M[i]>>j)&1:
                i0 = i
                break
        if i0 < 0:
            continue
        M[rank],M[i0] = M[i0],M[rank]
        b = _v_swap(b, rank, i0)
        for i in range(rank+1, r):
            if (M[i]>>j)&1:
                M[i] ^= M[rank]
                b ^= ((b>>rank)&1)<<i
        rank += 1
    # backwards resolution
    a = aset = 0
    for i in range(r-1, -1, -1):
        x = M[i]
        bi = (b>>i)&1
        unset = []
        while x:
            j = x&-x
            x &= x-1
            if aset&j:
                if a&j:
                    bi ^= 1
            else:
                unset.append(j)
        for j in unset:
            if bi:
                a |= j
                bi = 0
            aset |= j
        if bi:
            return None
    return a

def r_inverse(M: RMatrix):
    assert isinstance(M, RMatrix)
    assert M.r == M.c
    n,_,M = M
    M = list(M)  # copy / tuple -> list
    I = _id(n)
    for j in range(n):
        i0 = -1
        for i in range(j, n):
            if (M[i]>>j)&1:
                i0 = i
                break
        if i0 < 0:
            return None
        M[j],M[i0] = M[i0],M[j]
        I[j],I[i0] = I[i0],I[j]
        for i in range(n):
            if i != j and (M[i]>>j)&1:
                M[i] ^= M[j]
                I[i] ^= I[j]
    return RMatrix(n, n, I)


## Sanity checks
def _sanity_check1(it=100):
    # squaring operator matrix
    Sc = CMatrix(BS, BS, [poly2.pmodmul(1<<i, 1<<i) for i in range(BS)])

    k = 20  # for iterated squaring p -> p^(2^k) operator
    Mc = Sc
    Mr = cr_swap(Mc)
    for _ in range(k-1):
        Mc = rcc_mul(Mr, Sc)
        Mr = cr_swap(Mc)

    t0 = time.time()
    X = []
    for _ in range(it):
        x = random.randint(0, (1<<BS)-1)
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
    # constant mul operator matrix
    cst = random.randint(0, (1<<BS)-1)
    Mc = CMatrix(BS, BS, [poly2.pmodmul(cst, 1<<i) for i in range(BS)])
    Mr = cr_swap(Mc)

    t0 = time.time()
    X = []
    for _ in range(it):
        x = random.randint(0, (1<<BS)-1)
        z = poly2.pmodmul(cst, x)
        X.append((x, z))
    dt = time.time()-t0
    print(f'poly cst mul {dt:.3f} s')

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

def _sanity_check3(it=100):
    for _ in range(it):
        r = random.randint(1,100)
        c = random.randint(1,100)
        M = r_random(r, c)
        N = r_nullspace(M)
        assert all(rv_mul(M, v)==0 for v in N)

def _sanity_check4(it=100):
    for _ in range(it):
        r = random.randint(1,15)
        c = random.randint(1,15)
        M = r_random(r, c)
        b = random.randint(0, (1<<r)-1)
        a = r_system_solve(M, b)
        if a is None:
            for x in range(1<<c):
                assert rv_mul(M, x) != b
        else:
            assert rv_mul(M, a) == b

if __name__=='__main__':
    import time, poly2
    BS = poly2._K
    _sanity_check1()
    print()
    _sanity_check2()
    _sanity_check3()
    _sanity_check4()
