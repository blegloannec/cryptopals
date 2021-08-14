#!/usr/bin/env python3

# runs in ~2min

from lll import Decimal, Vec, LLL
import eccrypto as ec
from arith import invmodp
import os, secrets


def biased_sign(msg, d, l=8):
    k = secrets.randbelow(ec._Go>>l)<<l
    r = (k*ec._G).x % ec._Go
    s = ((ec.H(msg) + d*r) * invmodp(k,ec._Go)) % ec._Go
    return (r, s)


def attack():
    # consider DSA (mod q the order of G):
    #   random k                    (nonce / ephemeral DH private key)
    #   r = (k*G).x                 (ephemeral DH public key)
    #   s = ((H(msg) + d*r) * k^-1  (d the private key to guess)
    # and assume the last l bits (say l=8) of k are constant, say 0,
    # then k = b*2^l for some random b ~ q/2^l
    #   s*b*2^l = H(msg) + d*r
    #   b = -u + d*t for u = -H(msg)*s^-1*2^-l and t = r*s^-1*2^-l
    # with u, d*t ~ q >> q/2^l ~ b (for large enough l)
    # hence we can approx.
    #   0 ~ u - d*t  (mod q)
    #   0 ~ i + m*q - d*t for some integer m
    # say we capture n signatures, for i = 1..n
    #   0 ~ ui + mi*q - d*ti
    # where ui,ti,q are known, mi,d are unknown
    # let B = [q 0 0 .. 0 t1 u1]
    #         [0 q 0 .. 0 t2 u2]
    #         [0 0 q .. 0 t3 u3]
    #                ..
    #         [0 0 0 .. q tn un]
    #         [0 0 0 .. 0 ct  0]  <-- added to squarify the matrix
    #         [0 0 0 .. 0  0 cu]  <-- for some constants ct,cu
    # then B * [m1 .. mn -d 1] ~ [0 .. 0 -d*ct cu]
    q = ec._Go
    l = 8       # <-- the less bits known
    n = 20      # <-- the more signatures needed
    _d,_ = ec.gen_key(ec._G, ec._Go)
    B = []
    T = []
    U = []
    for i in range(n):
        msg = os.urandom(10)
        r,s = biased_sign(msg, _d, l)
        h = ec.H(msg)
        s2l_inv = invmodp(s*(1<<l), q)
        u = (-h * s2l_inv) % q
        t = (r * s2l_inv) % q
        T.append(t)
        U.append(u)
        B.append(Vec([q if j==i else 0 for j in range(n+2)]))
    ct = Decimal(1) / Decimal(1<<l)
    cu = Decimal(q) / Decimal(1<<l)
    T += [ct, 0]
    U += [ 0,cu]
    B += [Vec(T), Vec(U)]
    R = LLL(B)
    for v in R:
        if v[-1] == cu:
            d = -v[-2] / ct
            break
    print(d)
    print(_d)
    assert d == _d

if __name__=='__main__':
    attack()
