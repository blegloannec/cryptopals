#!/usr/bin/env python3

from Cryptodome.Util.number import getPrime, inverse
from collections import namedtuple

PrivKey = namedtuple('PrivKey', ('d', 'n'))
PubKey  = namedtuple('PubKey',  ('e', 'n'))

def gen_key(size=1<<10):
    e = 3  # we always want e = 3 here
    n = 0
    while n.bit_length()<size:
        p = getPrime(size>>1)
        while (p-1)%e == 0:  # gcd(e, p-1) != 1
            p = getPrime(size>>1)
        q = getPrime(size>>1)
        while (q-1)%e == 0:  # gcd(e, q-1) != 1
            q = getPrime(size>>1)
        n = p*q
    phi = (p-1)*(q-1)
    #d = pow(e, -1, phi)
    d = inverse(e, phi)
    K = PubKey(e, n)
    k = PrivKey(d, n)
    return (k, K)

def encrypt(K, m: int) -> int:
    e, n = K  # avoid K.e to allow signature ~ encrypt with PrivKey
    return pow(m, e, n)

# of course same as encrypt, but semantics...
def decrypt(k, c: int) -> int:
    d, n = k
    return pow(c, d, n)


# other helpers
int_to_bytes = lambda n: n.to_bytes((n.bit_length()+7)//8, 'big')

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, u, v = egcd(b, a%b)
    return (g, v, u-(a//b)*v)

def root3(c):
    # Newton's method with integers
    # f(x)  = x^3 - c
    # f'(x) = 3x^2
    x = x0 = 1 + (1<<(c.bit_length()//3))
    x -= (x**3-c) // (3*x**2)
    while x != x0:
        x0 = x
        x2 = x*x
        x -= (x2*x-c) // (3*x2)
    x -= 1
    #assert x**3 == c
    return x
