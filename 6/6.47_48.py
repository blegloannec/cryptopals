#!/usr/bin/env python3

import rsalib
from rsalib import int_to_bytes
import Cryptodome.Random.random as random
from Cryptodome.Util.number import inverse, ceil_div
# Alternatively: ceil_div = lambda p,q: (p+q-1)//q
#                inverse  = lambda x,n: pow(x, -1, n)


## Padding & oracle
def pad(D: bytes, k: int) -> bytes:
    assert len(D) <= k-11
    P = bytes(random.randint(1, 255) for _ in range(k-3-len(D)))
    return b'\x00\x02' + P + b'\x00' + D

def is_PKSC1_conform(EB: bytes) -> bool:
    return EB[0]==0x00 and EB[1]==0x02 \
        and all(EB[i]!=0x00 for i in range(2, 10)) \
        and any(EB[i]==0x00 for i in range(10, len(EB)))

# faster check to focus on what actually matters here
def fast_is_PKSC1_conform(EB: bytes) -> bool:
    return EB[0]==0x00 and EB[1]==0x02

def unpad(EB: bytes) -> bytes:
    assert is_PKSC1_conform(EB)
    i = next(i for i in range(10, len(EB)) if EB[i]==0x00)
    return EB[i+1:]

def oracle(x: int) -> bool:
    mess = rsalib.decrypt(_k, x).to_bytes(k, 'big')
    return fast_is_PKSC1_conform(mess)


# Let B = 2^(8(k-2)), the oracle tells us
#   2B ≤ decrypt(x) < 3B  [mod n]
# Assume we have c = encrypt(m), then for any s,
#   oracle(s^e*c)  <=>  ∃r, 2B + rn ≤ sm < 3B + rn
# Assume furthermore that we know that a ≤ m ≤ b.
# Note that to wrap the modulus (r > 0), we want
# n ≤ sm ≤ sb, hence a sufficient condition is s ≥ n/b.
# If we find such s, then we won't exactly know r as
# the inequality is given mod n, but we can bound
#   sa-3B < sm-3B < rn ≤ sm-2B ≤ sb-2B
# hence
#   (as-3B+1)/n ≤ r ≤ (bs-2B)/n
# Assuming we consider such a candidate value for r,
# then we would have
#    2B+rn    ≤ sm ≤  3B-1+rn    < 3B+rn
# hence
#   (2B+rn)/s ≤  m ≤ (3B-1+rn)/s
# and we could then refine
#   max(a, (2B+rn)/s) ≤ m ≤ min(b, (3B-1+rn)/s)
# This analysis enlightens the design of steps 2a, 2b & 3.
# Step 2c intends to accelerate the search by splitting
# the interval roughly in half...

def merge_intervals(I):
    I.sort()
    O = []
    for l,r in I:
        if O and l <= O[-1][1]:
            O[-1] = (O[-1][0], max(O[-1][1],r))
        else:
            O.append((l,r))
    return O

def attack(c : bytes):
    e,n = K
    B = 1<<(8*(k-2))
    
    # Init.
    print('Step  1......', end=' ', flush=True)
    if oracle(c):  # m was already padded before encryption
        s0 = 1
    else:
        # Step 1
        s0 = random.randint(0, n-1)
        while not oracle(c*pow(s0,e,n)):
            s0 = random.randint(0, n-1)
    M = [(2*B, 3*B-1)]
    c0 = (c*pow(s0,e,n)) % n
    i = 1
    print('ok.')
    
    # Step 2.a
    print('Step  2a.....', end=' ', flush=True)
    s = ceil_div(n, 3*B)
    while not oracle(c0*pow(s,e,n)):
        s += 1
    print('ok.')
    
    while True:
        print(f'Steps 2b-4... {i}', end='\r', flush=True)
        if len(M) > 1:
            # Step 2.b
            s += 1
            while not oracle(c0*pow(s,e,n)):
                s += 1
        else:
            # Step 2.c
            a,b = M[0]
            r = ceil_div(2*(b*s-2*B), n)
            s = ceil_div(2*B+r*n, b)
            while not oracle(c0*pow(s,e,n)):
                s += 1
                if a*s >= 3*B+r*n:
                    r += 1
                    s = ceil_div(2*B+r*n, b)
        
        # Step 3
        Mupd = []
        for a,b in M:
            r = ceil_div(a*s-3*B+1, n)
            while n*r <= b*s-2*B:
                a1 = max(a, ceil_div(2*B+r*n, s))
                b1 = min(b, (3*B-1+r*n)//s)
                if a1 <= b1:
                    Mupd.append((a1,b1))
                r += 1
        M = merge_intervals(Mupd)
        
        # Step 4
        if len(M) == 1 and M[0][0] == M[0][1]:
            return (M[0][0]*inverse(s0,n)) % n
        i += 1


if __name__=='__main__':
    # Sanity check
    print('Sanity check...', end=' ', flush=True)
    k = 96  # byte length of the key (article notation)
    _k, K = rsalib.gen_key(8*k)
    m0 = b'simple_test'
    p = pad(m0, k)
    assert is_PKSC1_conform(p)
    c = rsalib.encrypt(K, int.from_bytes(p, 'big'))
    assert oracle(c)
    d = rsalib.decrypt(_k, c).to_bytes(k, 'big')
    assert is_PKSC1_conform(d)
    m1 = unpad(d)
    assert m1 == m0
    print('ok.\n')
    
    # 6.47
    k = 1<<5  # byte length of the key (article notation)
    _k, K = rsalib.gen_key(8*k)
    print(f'Key size = {K.n.bit_length()}')
    _MSG = b'kick it, CC'
    CIPH = rsalib.encrypt(K, int.from_bytes(_MSG, 'big'))
    deciph = int_to_bytes(attack(CIPH))  # attack
    print(f'\n{deciph}\n')
    assert deciph == _MSG
    
    # 6.48
    k = 96
    _k, K = rsalib.gen_key(8*k)
    print(f'Key size = {K.n.bit_length()}')
    _MSG = b"That's why I found you don't play around with the Funky Cold Medina"
    # this time we pad to save time
    CIPH = rsalib.encrypt(K, int.from_bytes(pad(_MSG, k), 'big'))
    deciph = unpad(attack(CIPH).to_bytes(k, 'big'))  # attack
    print(f'\n{deciph}')
    assert deciph == _MSG
