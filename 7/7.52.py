#!/usr/bin/env python3

import sys
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
    Pred = {}
    while True:
        B = get_random_bytes(BS)
        H = compression(H0, B)
        if H in Pred and Pred[H] != B:
            return (Pred[H], B)
        Pred[H] = B

def gen_2n_collisions(H: bytes, n):
    M = []
    for _ in range(n):
        M.append(random_collision(H))
        H = compression(H, M[-1][0])
    return M


## ===== Double MD ===== ##
def double_md(H1: bytes, H2: bytes, M: bytes) -> bytes:
    return merkle_damgard(H1, M) + merkle_damgard(H2, M)


if __name__=='__main__':
    # Simple MD collisions
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

    # Double MD collision
    HS1 = 3
    HS2 = 4
    n   = 4*HS2  # gen. 2^(8*HS2/2) candidates
    H01 = get_random_bytes(HS1)
    H02 = get_random_bytes(HS2)
    print(f'H01 = {H01.hex()} of size {8*HS1} bits')
    print(f'H02 = {H02.hex()} of size {8*HS2} bits')
    while True:
        print(f'Generating 2^{n} collisions for the size {8*HS1} hash...', end=' ', flush=True)
        M = gen_2n_collisions(H01, n)
        print('ok.')
        print(f'Looking for a collision for the size {8*HS2} hash...', end=' ', flush=True)
        Pred = {}
        for P in itertools.product(*M):
            M0 = b''.join(P)
            H = merkle_damgard(H02, M0)
            if H in Pred:
                M1, M2 = Pred[H], M0
                assert M1 != M2
                print('found!')
                print(f'M1 = {M1.hex()}')
                print(f'M2 = {M2.hex()}')
                H1 = double_md(H01, H02, M1)
                H2 = double_md(H01, H02, M2)
                assert H1 == H2
                print(f'H  = {H1.hex()}')
                sys.exit()
            Pred[H] = M0
        print('not found, trying again.')
