#!/usr/bin/env python3

_MOD = (1<<128) | (1<<7) | (1<<2) | (1<<1) | 1
_K = 128


## === Polynomials in GF(2)[X] === ##
# coeffs are represented by the bits of an int
# add is xor (+ is ^)

def deg(a):
    return a.bit_length()-1  # -1 for 0

def pmul(a,b):
    # A×B = (∑aᵢXⁱ)×B = ∑aᵢBXⁱ
    p = 0
    while a:
        # at the i-th iteration, a&1 == aᵢ and b == BXⁱ
        if a&1:
            # if aᵢ, we add BXⁱ to the result
            p ^= b
        a >>= 1
        b <<= 1
    return p

def pdivmod(a, b):
    q = 0
    while deg(a) >= deg(b):
        d = deg(a) - deg(b)
        q ^= 1<<d  # Q += X^d
        a ^= b<<d  # A -= BX^d
    return (q, a)

def pdiv(a, b):
    q, _ = pdivmod(a, b)
    return q

def pmod(a, b=_MOD):
    _, r = pdivmod(a, b)
    return r


# Sanity check
def _sanity_check_1(it=20):
    for _ in range(it):
        a = random.randint(0, 1<<1024)
        b = random.randint(0, 1<<256)
        q,r = pdivmod(a,b)
        assert deg(r) < deg(b) and a == pmul(q,b)^r


## === Polynomials in GF(2^k) ~ GF(2)[X] / (an irreducible poly of deg. k) === ##

def _pmodmul(a, b, m=_MOD):  # naive 2-step version
    return pmod(pmul(a, b), m)

def pmodmul(a, b, m=_MOD):   # accelerated version
    #assert deg(a) < deg(m) and deg(b) < deg(m)
    p = 0
    while a:
        if a&1:
            p ^= b
        a >>= 1
        b <<= 1
        if deg(b) == deg(m):
            b ^= m
    return p

def pegcd(a, b):
    if b==0:
        return (a, 1, 0)
    g, u, v = pegcd(b, pmod(a, b))
    return (g, v, u^pmul(pdiv(a, b), v))

def pmodinv(a, m=_MOD):
    g, u, _ = pegcd(a, m)
    assert g == 1
    return u

def pmodexp(a, n, m=_MOD):
    if n == 0:
        return 1
    if n&1 == 0:
        return pmodexp(pmodmul(a, a, m), n>>1, m)
    return pmodmul(a, pmodexp(pmodmul(a, a, m), n>>1, m), m)

def _pmodexp(a, n, m=_MOD):
    # alt. implem. to compare perf.
    x = 1
    for k in range(n.bit_length()-1, -1, -1):
        x = pmodmul(x, x, m)
        if (n>>k)&1:
            x = pmodmul(x, a, m)
    return x

def __pmodexp(a, n, m=_MOD):
    # yet another alt. implem. to compare perf.
    x = 1
    while n:
        if n&1:
            x = pmodmul(x, a, m)
        a = pmodmul(a, a, m)
        n >>= 1
    return x


# Sanity check
def _sanity_check_2(it=20):
    for _ in range(it):
        a = random.randint(0, 1<<_K)
        b = random.randint(0, 1<<_K)
        assert _pmodmul(a, b) == pmodmul(a, b)

        ainv = pmodinv(a)
        assert pmodmul(a, ainv) == 1
        assert ainv == pmodexp(a, (1<<_K)-2)


## === Polynomials in GF(2^k)[X] === ##

from itertools import zip_longest
from copy import copy

class Poly2k:
    def __init__(self, C=None):
        if C is None:
            self.C = []
        else:
            self.C = [pmod(c) for c in C]
            self.reduce()

    def deg(self):
        return len(self.C)-1

    def reduce(self):
        while self.C and self.C[-1]==0:
            self.C.pop()

    def __getitem__(self, i):
        assert i >= 0
        return self.C[i] if i <= self.deg() else 0

    def __setitem__(self, i, x):
        assert i >= 0
        if i > self.deg():
            self.C += [0]*(i-self.deg())
        self.C[i] = x
        self.reduce()

    def __add__(self, B):
        return Poly2k([a^b for a,b in zip_longest(self.C, B.C, fillvalue=0)])

    __sub__ = __add__

    def __mul__(self, B):
        C = [0]*(len(self.C)+len(B.C)-1)
        for i,a in enumerate(self.C):
            for j,b in enumerate(B.C):
                C[i+j] ^= pmodmul(a, b)
        return Poly2k(C)

    def __lshift__(self, d):
        return Poly2k([0]*d + self.C)

    def __rmul__(self, p):
        assert isinstance(p, int)  # p in GF(2^k)
        return Poly2k([pmodmul(p, c) for c in self.C])

    def divmod(self, B):
        assert B.deg() >= 0
        R = copy(self)
        Q = Poly2k()
        while R.deg() >= B.deg():
            d = R.deg() - B.deg()
            q = pmodmul(R.C[-1], pmodinv(B.C[-1]))
            #Q += Poly2k([q])<<d
            Q[d] ^= q
            R -= q*(B<<d)
        return (Q, R)

    def __floordiv__(self, Q):
        Q, _ = self.divmod(Q)
        return Q

    __truediv__ = __floordiv__

    def __mod__(self, Q):
        _, R = self.divmod(Q)
        return R

    def gcd(self, Q):
        if Q.deg() < 0:
            return copy(self)
        return Q.gcd(self % Q)

    def __str__(self):
        return str(self.C)

    def __eq__(self, B):
        return self.C == B.C


def rand_poly2k(d, k=_K):
    return Poly2k([random.randint(0, 1<<k) for _ in range(d+1)])


# Sanity check
def _sanity_check_3(it=20): 
    for _ in range(it):
        A = rand_poly2k(15)
        B = rand_poly2k(10)
        C = A*B
        Q,R = C.divmod(B)
        assert Q == A and R.deg() < 0

        Q,R = A.divmod(B)
        assert R.deg() < B.deg() and Q*B+R == A


## === MAIN === ##
if __name__=='__main__':
    import random
    random.seed()
    _sanity_check_1()
    _sanity_check_2()
    _sanity_check_3()