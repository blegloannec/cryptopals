#!/usr/bin/env python3

import rsalib
from rsalib import int_to_bytes
from decimal import Decimal, getcontext
from Cryptodome.Random import get_random_bytes
import base64

mess0 = b'platypus@monotremes:'+base64.b64encode(get_random_bytes(9))
m0 = int.from_bytes(mess0, 'big')
print(mess0, hex(m0))

def gen_encrypt(m):
    _, K = rsalib.gen_key(m.bit_length()+3)
    e, n = K
    assert e == 3
    return n, rsalib.encrypt(K, m)

n1, c1 = gen_encrypt(m0)
n2, c2 = gen_encrypt(m0)
n3, c3 = gen_encrypt(m0)
# modular system
# { m^3 = c1 mod n1
# { m^3 = c2 mod n2
# { m^3 = c3 mod n3

# assume gcd(n1, n2) == 1
# using Bezout, we have u*n1 + v*n2 = 1
# (where u = n1^(-1) mod n1 and v = n2^(-1) mod n1)
# hence    x = r2*u*n1 + r1*v*n2 mod n1*n2
# verifies x = r1*v*n2 = r1 mod n1
# and      x = r2*u*n1 = r2 mod n2

def crt(r1, n1, r2, n2):
    g, u, v = rsalib.egcd(n1, n2)
    assert g == 1
    return (r2*u*n1 + r1*v*n2) % (n1*n2)

c12 = crt(c1, n1, c2, n2)
c123 = crt(c12, n1*n2, c3, n3)

getcontext().prec = c123.bit_length()//3
m1 = round(Decimal(c123)**(Decimal(1)/Decimal(3)))
mess1 = int_to_bytes(m1)
print(mess1, hex(m1))
assert mess1 == mess0
