#!/usr/bin/env python3

from Crypto.Util.number import getPrime

def gen_key(size=1<<10):
    e = 3  # we always want e = 3 here
    p = getPrime(size>>1)
    while (p-1)%e == 0:  # gcd(e, p-1) != 1
        p = getPrime(size>>1)
    q = getPrime(size>>1)
    while (q-1)%e == 0:  # gcd(e, q-1) != 1
        q = getPrime(size>>1)
    n = p*q
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    K = (e, n)
    k = (d, n)
    return (k, K)

def encrypt(K, m):
    e, n = K
    return pow(m, e, n)

# of course same as encrypt, but semantics...
def decrypt(k, c):
    d, n = k
    return pow(c, d, n)


# other helpers
int_to_bytes = lambda n: n.to_bytes((n.bit_length()+7)//8, 'big')

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, u, v = egcd(b, a%b)
    return (g, v, u-(a//b)*v)
