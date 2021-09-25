#!/usr/bin/env python3

import dsalib
from dsalib import p, q
from Cryptodome.Random.random import randint

## Once again, the statement is not really clear...
# The attacks mentionned are from
# S. Vaudenay, The Security of DSA and ECDSA
# https://www.iacr.org/archive/pkc2003/25670309/25670309.pdf
# and actually assume that "we can corrupt g in the memory"
# (so at some point within the process, and typically before
#  some call to dsa_verify, while the user key is already fixed)

_, y = dsalib.gen_user_key()
msgs = (b'Hello, world', b'Goodbye, world')

## Case g = 0
# Let us consider what happens (independently, no common assumption other
# than g = 0) in each of our primitives from dsalib.py
# gen_user_key -> x random, y = 0
# dsa_sign     -> r = 0 (REJECTED), s = h/k (h = Hash(msg), k random)
# dsa_verify   -> v = 0^(h/s) * y^(r/s) = 0
#   any message could be verified with any signature of the
#   form (0, s) with any s ≠ 0 mod q
#   except our implementation REJECTS r = 0

## Case g = p+1 = 1 mod p
# gen_user_key -> x random, y = 1
# dsa_sign     -> r = 1, s = (h+x)/k (h = Hash(msg), k random)
# dsa_verify   -> v = 1^(h/s) * y^(r/s)
#   we want y^(r/s) = r mod p mod q
#   let us write r = y^z for some z
#   this reduces to r/s = z mod q, hence s = z/r mod q
#   hence any message can be verified with any signature of the
#   form (r = y^z mod p mod q, s = r/z mod q) with any z ≠ 0 mod q

dsalib.g = p+1

def randsig():
    z = randint(1, q-1)
    r = pow(y, z, p) % q
    s = (r*pow(z, -1, q)) % q
    return (r, s)

for msg in msgs:
    print(f'Verifying {msg}...', end='\t', flush=True)
    sig = randsig()
    assert dsalib.dsa_verify(y, msg, sig)
    print('ok')
