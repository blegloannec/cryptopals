#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import itertools

BS = 16


## ===== Simple MD ===== ##
def compression(H: bytes, B: bytes) -> bytes:
    HS = len(H)
    assert len(H) <= BS
    assert len(B) == BS
    return AES.new(H+bytes(BS-HS), AES.MODE_ECB).encrypt(B)[:HS]

def merkle_damgard(H: bytes, M: bytes) -> bytes:
    M = pad(M, BS)  # not the usual MD padding, but whatever...
    for i in range(0, len(M), BS):
        H = compression(H, M[i:i+BS])
    return H

def random_collision(H0: bytes):
    # O(√ hash bit length) by "birthday attack"
    Pred = {}
    while True:
        B = get_random_bytes(BS)
        H = compression(H0, B)
        if H in Pred and Pred[H] != B:
            return (Pred[H], B)
        Pred[H] = B

def gen_2n_collisions(H: bytes, n: int):
    # generates 2ⁿ collisions for merkle_damgard(H, .)
    # given as a list of length n of couples of blocks
    MM = []
    for _ in range(n):
        MM.append(random_collision(H))
        H = compression(H, MM[-1][0])
    return MM

if __name__=='__main__':
    HS = 3
    n  = 10
    H0 = get_random_bytes(HS)
    print(f'H0 = {H0.hex()} of size {8*HS} bits')
    MM = gen_2n_collisions(H0, n)
    H1 = None
    for BT in itertools.product(*MM):
        M = b''.join(BT)
        H = merkle_damgard(H0, M)
        if H1 is None:
            H1 = H
            print(f'H  = {H.hex()}')
            print(f'Checking 2^{n} collisions...', end=' ', flush=True)
        else:
            assert H == H1
    print('ok.\n')


## ===== Double MD ===== ##
def double_md(H1: bytes, H2: bytes, M: bytes) -> bytes:
    return merkle_damgard(H1, M) + merkle_damgard(H2, M)

def brute_collisions(MM, H0):
    # naive approach considering the second hash as a black-box
    Pred = {}
    for P in itertools.product(*MM):
        M0 = b''.join(P)
        H = merkle_damgard(H0, M0)
        if H in Pred:
            yield (Pred[H], M0)
        else:
            Pred[H] = M0

def backtrack_md_collisions(_Pred, MM, H0, M=b'', i=0):
    # much faster approach computing the MD hash on-the-fly
    if i==len(MM):
        if H0 in _Pred:
            yield (_Pred[H0], M)
        else:
            _Pred[H0] = M
    else:
        for B in MM[i]:
            yield from backtrack_md_collisions(_Pred, MM, compression(H0, B), M+B, i+1)

if __name__=='__main__':
    HS1 = 3
    HS2 = 4
    n   = 4*HS2  # gen. 2^(8*HS2/2) candidates
    H01 = get_random_bytes(HS1)
    H02 = get_random_bytes(HS2)
    print(f'H01 = {H01.hex()} of size {8*HS1} bits')
    print(f'H02 = {H02.hex()} of size {8*HS2} bits')
    while True:
        print(f'Generating 2^{n} collisions for the size {8*HS1} hash...', end=' ', flush=True)
        MM = gen_2n_collisions(H01, n)
        print('ok.')
        print(f'Looking for a collision for the size {8*HS2} hash...', end=' ', flush=True)
        try:
            #M1, M2 = next(brute_collisions(MM, H02))
            M1, M2 = next(backtrack_md_collisions({}, MM, H02))
            assert M1 != M2
            H1 = double_md(H01, H02, M1)
            H2 = double_md(H01, H02, M2)
            assert H1 == H2
            print('found!')
            print(f'M1 = {M1.hex()}')
            print(f'M2 = {M2.hex()}')
            print(f'H  = {H1.hex()}')
            break
        except StopIteration:
            print('not found, trying again.')
