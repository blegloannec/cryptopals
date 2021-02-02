#!/usr/bin/env python3

#from math import gcd
from Crypto.Util.number import getPrime
from Cryptodome.Random import get_random_bytes
import base64

## == handmade modular inverse == ##
def bezout(a, b):
    if b == 0:
        return (a, 1, 0)
    g, u, v = bezout(b, a%b)
    return (g, v, u-(a//b)*v)

# same as Crypto.Util.number.inverse(a, n)
# or simply pow(a, -1, n) since Python 3.8
def inv_mod(a, n):
    g, u, _ = bezout(a,n)
    assert g==1
    return u%n
## == ##

int_to_bytes = lambda n: n.to_bytes((n.bit_length()+7)//8, 'big')

def gen_rsa_key(size=1<<10):
    e = 3  # we always want e = 3 here
    p = getPrime(size>>1)
    while (p-1)%e == 0:  # gcd(e, p-1) != 1
        p = getPrime(size>>1)
    q = getPrime(size>>1)
    while (q-1)%e == 0:  # gcd(e, q-1) != 1
        q = getPrime(size>>1)
    n = p*q
    phi = (p-1)*(q-1)
    d = inv_mod(e, phi)
    K = (e, n)
    k = (d, n)
    return (k, K)

def rsa_encrypt(K, m):
    e, n = K
    return pow(m, e, n)

# of course same as encrypt, but semantics...
def rsa_decrypt(k, c):
    d, n = k
    return pow(c, d, n)

if __name__=='__main__':
    mess0 = b'platypus@cryptopals:'+base64.b64encode(get_random_bytes(9))
    m0 = int.from_bytes(mess0, 'big')
    k, K = gen_rsa_key(m0.bit_length()+3)
    print(mess0, hex(m0))
    c = rsa_encrypt(K, m0)
    m1 = rsa_decrypt(k, c)
    mess1 = int_to_bytes(m1)
    print(mess1, hex(m1))
    assert mess1 == mess0
