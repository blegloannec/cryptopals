#!/usr/bin/env python3

_MOD = (1<<128) | (1<<7) | (1<<2) | (1<<1) | 1
_K = 128


import sys, random
sys.setrecursionlimit(10000)  # for recursive fast exp. implem.
random.seed()


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
    res = pmodexp(pmodmul(a, a, m), n>>1, m)
    if n&1:
        res = pmodmul(res, a, m)
    return res

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
        elif isinstance(C, int):
            self.C = [C]
        else:
            self.C = [pmod(c) for c in C]
        self.reduce()

    def deg(self):
        return len(self.C)-1

    def reduce(self):
        while self.C and self.C[-1] == 0:
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

    def __rmul__(self, p):  # scalar mul.
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
        if Q == 0:
            return self.to_monic()
        return Q.gcd(self % Q)

    def __str__(self):
        return str(self.C)

    __repr__ = __str__

    def __eq__(self, B):
        if isinstance(B, int):  # for Poly2k == int comparison
            if B == 0:
                return self.deg() < 0
            return self.deg() == 0 and self.C[0] == B
        return self.C == B.C  # assuming reduced

    def __pow__(self, n):
        #assert n >= 0
        if n == 0:
            return Poly2k(1)
        res = (self*self)**(n>>1)
        if n&1:
            res *= self
        return res

    def to_monic(self):
        assert self.deg() >= 0
        return pmodinv(self.C[-1])*self

    def diff(self):  # derivation (for q = 2^k, p = 2 => fallen exponents mod p)
        return Poly2k([self.C[i] if i&1!=0 else 0 for i in range(1, len(self.C))])

    def sqrt(self):
        # through Frobenius morphism x -> x^p for p = 2
        # (∑ ai X^i)^p = ∑ ai^p X^(i*p)
        # in GF(p^k), we have x^(p^k) = x
        #             (x^p)^(p^(k-1)) = x
        # hence the inverse of Frobenius is x -> x^(p^(k-1))
        assert all(c == 0 for c in self.C[1::2])
        return Poly2k([pmodexp(c, 1<<(_K-1)) for c in self.C[::2]])

    def modexp(self, n, MOD):
        #assert n >= 0
        if n == 0:
            return Poly2k(1)
        res = ((self*self)%MOD).modexp(n>>1, MOD)
        if n&1:
            res = (res*self) % MOD
        return res

    def factorization(self):
        P = self.to_monic()
        for Q,m in square_free_factorization(P):
            for R,d in distinct_degree_factorization(Q):
                for u in equal_degree_factorization(R, d):
                    yield (u, m)

    def roots(self):
        # relies on factorization, except
        # we are only interested in factors of degree 1
        P = self.to_monic()
        for Q,_ in square_free_factorization(P):
            for R,d in distinct_degree_factorization(Q, 1):
                assert d == 1
                for u in equal_degree_factorization(R, d):
                    yield u[0]

    def __call__(self, x):
        y = 0
        for c in reversed(self.C):
            y = pmodmul(y, x) ^ c
        return y


def rand_poly2k(d, k=_K):
    return Poly2k([random.randint(0, 1<<k) for _ in range(d+1)])

def rand_monic_poly2k(d, k=_K):
    return Poly2k([random.randint(0, 1<<k) for _ in range(d)]+[1])


## === Factorization === ##
# https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields

def square_free_factorization(P, b=1):
    # Input:  A monic polynomial P in Fq[x] where q = p^k, p = 2
    # Output: Pairs (Q, m) where Q is a square-free polynomial
    #         such that P = ∏ Q^m

    # Make W be the product (without multiplicity) of all
    # factors of P that have multiplicity not divisible by p = 2
    # if P = ∏ Ri^ai
    # then C = GCD(P, P') =   ∏_{ai%p≠0} Ri^(ai-1)
    #                       × ∏_{ai%p=0} Ri^ai     if prod. above is non-empty
    #                     = 0                      otherwise
    # and W = P/C = ∏_{ai%p≠0} Ri
    C = P.gcd(P.diff())
    W = P//C

    # Identify all factors in W
    i = 1
    while W != 1:
        Y = W.gcd(C)
        Z = W//Y
        # at iteration i:
        #   Y = ∏_{ai%p≠0 & ai>i} Ri
        #   Z = ∏_{ai%p≠0 & ai=i} Ri
        if Z != 1:
            yield (Z, b*i)
        W = Y
        C //= Y
        i += 1
    # C is now the product (with multiplicity) of the remaining factors of P
    # C = ∏_{ai%p=0} Ri^ai is a p-power
    # Identify all remaining factors using recursion
    if C != 1:
        yield from square_free_factorization(C.sqrt(), 2*b)


def distinct_degree_factorization(P, deg_max=1<<30):
    # Input:  A monic square-free polynomial P in Fq[x] where q = p^k, p = 2
    # Output: Pairs (Q, d) where Q is the product of all factors of degree d in P
    # deg_max: optional parameter to bound the degree of the
    #          returned factors (when only interested by small degrees)
    X = Poly2k([0,1])
    q = 1<<_K

    i = 1  # current degree
    F = P  # current product
    Xqi = X
    # while the current product can contain at least 2 factors of degree i
    while F.deg() >= 2*i and i <= deg_max:
        # Thm: X^(q^i) - X is the product of all monic irreducible poly.
        #      of degree dividing i.         [non-trivial useful result]
        # hence GCD(F, X^(q^i)-X) = product of all factors of degree i in F       
        Xqi = Xqi.modexp(q, F)  # good enough way to compute X^(q^i) mod F
        # (see sanity check 4 below for a faster approach taking advantage
        #  of the linearity of x -> x^k over GF(q)[x]/(F))
        G = F.gcd(Xqi - X)
        if G != 1:
            yield (G, i)
            F //= G
        i += 1
    if F != 1 and F.deg() <= deg_max:
        # one remaining factor
        yield (F, F.deg())


def equal_degree_factorization(f, d):  # Cantor-Zassenhaus
    # Input:  f a monic square-free product of factors of degree d
    # Output: the factors of f (all of degree d)
    n = f.deg()
    #assert n%d == 0
    # f is the product of n/d irreducible factors of deg. d.
    # For any such factor fi, GF(q)[x]/(fi) ~ GF(q^d)
    # with q = 2^128 = 1 mod 3, hence 3 | q^d-1, hence
    # there exists a subgroup of order 3 in GF(q^d)*
    # Elevating a random element h to the power e = (q^d-1)/3,
    # we land into that subgroup and have a 1/3 chance to
    # land on 1, but then h^e-1 = 0 mod fi  (fi | h^e-1)
    e = ((1<<_K)**d-1)//3
    # We do not know the fi's, but we can take a random h mod f
    # and compute g = gcd(h^e-1, f). For each fi, there is a 1/3
    # chance that fi | g, hence g roughly splits f into 1/3 & 2/3
    # of its factors (this is an implicit application of the CRT
    # on GF(q)[x]/(f) ~ ∏ GF(q)[x]/(fi)).
    # Then repeat with other h on the resulting non-fully split
    # factors...
    S = [f]  # current set of factors
    while S:
        h = rand_monic_poly2k(n-1)
        g = h.gcd(f)
        if g == 1:
            g = (h.modexp(e, f) - Poly2k(1)) % f

        T = []
        for u in S:
            if u.deg() == d:  # fully-split -> output
                yield u
            else:
                #assert u.deg() > d
                v = g.gcd(u)
                if v != 1 and v != u:
                    T.append(v)
                    T.append(u//v)
                else:
                    T.append(u)
        S = T


# Sanity check
def _sanity_check_3(it=1):
    for _ in range(it):
        C = rand_monic_poly2k(random.randint(1,20))
        D = Poly2k(1)
        for R,a in C.factorization():
            D *= R**a
        assert D == C

def _sanity_check_4(it=5):
    # On computing X^(q^i) mod F (can be useful in DDF and EDF)...
    # Remember Frobenius morphism x -> x^p in a ring of characteristic p.
    # Let q = p^k for some k. Over GF(q), x -> x^q is the identity.
    # Given some polynomial F, in the ring GF(q)[x]/(F) seen as
    # a GF(q) vector space of dim. d = d°F, the map x -> x^q is linear.
    q = 1<<_K
    F = rand_poly2k(random.randint(2, 10))
    # Pre-computing this map over the canonical basis (1, ..., X^(d-1))
    # allows a faster computation than by fast modular expo.
    Canon = [Poly2k(1), Poly2k([0,1]).modexp(q, F)]
    for k in range(2, F.deg()):
        Canon.append((Canon[-1]*Canon[1]) % F)

    for _ in range(it):
        P = rand_poly2k(F.deg()-1)
        Pq = Poly2k(0)
        for p,qi in zip(P.C, Canon):
            Pq += p*qi
        assert Pq == P.modexp(q, F)


## === MAIN === ##
if __name__=='__main__':
    _sanity_check_1()
    _sanity_check_2()
    _sanity_check_3()
    _sanity_check_4()
