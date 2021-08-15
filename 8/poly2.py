#!/usr/bin/env python3

## Polynomials in GF(2)[X]
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

def pmod(a, b):
    _, r = pdivmod(a, b)
    return r


## Polynomials in GF(2^k) ~ GF(2)[X] / (an irreducible poly of deg. k)

def _pmodmul(a, b, m):  # naive 2-step version
    return pmod(pmul(a, b), m)

def pmodmul(a, b, m):   # accelerated version
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


if __name__=='__main__':
    # sanity check
    import secrets
    m = (1<<128)|(1<<7)|(1<<2)|(1<<1)|1
    for _ in range(1000):
        a = secrets.randbelow(1<<1024)
        b = secrets.randbelow(1<<256)
        q,r = pdivmod(a,b)
        assert deg(r) < deg(b) and a == pmul(q,b)^r
        a = pmod(a, m)
        b = pmod(b, m)
        assert _pmodmul(a, b, m) == pmodmul(a, b, m)
