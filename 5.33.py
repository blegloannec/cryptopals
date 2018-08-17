#!/usr/bin/env python3

import random
random.seed()

p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff',16)
g = 2

def gen_key(p,g):
    a = random.randint(1,p-1)
    A = pow(g,a,p)
    return a,A

a,A = gen_key(p,g)
b,B = gen_key(p,g)

sa = pow(B,a,p)
sb = pow(A,b,p)
assert(sa==sb)
