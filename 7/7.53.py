#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import itertools

BS = 16
HS = 3   # hash size = HS bytes = 8*HS bits

# we reuse the MD setup of 7.52
def md_pad(M: bytes) -> bytes:
    ml = len(M)
    k = (-ml-1-8) % BS
    return M + b'\x80' + bytes(k) + (8*ml).to_bytes(8, 'big')

def compression(H: bytes, B: bytes) -> bytes:
    assert len(H) == HS
    assert len(B) == BS
    return AES.new(H+bytes(BS-HS), AES.MODE_ECB).encrypt(B)[:HS]

def _md(H, M):
    for i in range(0, len(M), BS):
        H = compression(H, M[i:i+BS])
    return H

def merkle_damgard(H: bytes, M: bytes) -> bytes:
    return _md(H, md_pad(M))


def random_collision(H01: bytes, H02: bytes):
    # finds A & B such that compression(H01, A) == compression(H02, B)
    # O(2^(8*HS/2)) by birthday attack
    Pred = {}
    while True:
        B = get_random_bytes(BS)
        H1 = compression(H01, B)
        if H1 in Pred:
            if Pred[H1][1] is not None:
                return (B, Pred[H1][1])
        else:
            Pred[H1] = (B, None)
        H2 = compression(H02, B)
        if H2 in Pred:
            if Pred[H2][0] is not None:
                return (Pred[H2][0], B)
        else:
            Pred[H2] = (None, B)


class ExpandableMsg:
    def __init__(self, H: bytes, k: int):
        # expected O(2^k + k*2^(8*HS/2))
        self.EM = []
        self.k = k
        self.H0 = H
        for n in range(self.k):
            M = get_random_bytes(BS<<n)
            H2 = _md(H, M)
            A,B = random_collision(H, H2)
            self.EM.append((A, M+B))
            H = compression(H, A)
        self.Hf = H

    def expand_to(self, l: int) -> bytes:
        l -= self.k
        assert 0 <= l < 1<<self.k
        return b''.join(self.EM[i][(l>>i)&1] for i in range(self.k))


if __name__=='__main__':
    H0 = get_random_bytes(HS)
    k = 4*HS
    print(f'hash size = {HS} bytes, k = {k}')

    print('Pre-computing expandable message...', end=' ', flush=True)
    EM = ExpandableMsg(H0, k)
    print('ok.')

    print('Computing original message mapping...', end=' ', flush=True)
    # we have chosen len(X) ~ 2^(8*HS/2) here
    X = get_random_bytes(BS<<k)
    H2idx = {}
    H = H0
    for i in range(0, len(X), BS):
        H = compression(H, X[i:i+BS])
        j = i//BS+1
        if j-1 >= k:
            H2idx[H] = j
    print('ok.')

    print('Randomly looking for a bridge...', end=' ', flush=True)
    # proba:    len(X)/2^(8*HS)
    # expected time: 1/proba    ~ 2^(8*HS/2) for the chosen len(X) here
    H = None
    t = 0
    while H not in H2idx:
        Bridge = get_random_bytes(BS)
        H = compression(EM.Hf, Bridge)
        t += 1
    print(f'ok ({t} tries).')

    print('Building and checking second pre-image:')
    l = H2idx[H]
    X1 = EM.expand_to(l-1) + Bridge + X[l*BS:]
    assert len(X1) == len(X)
    Y = merkle_damgard(H0, X)
    Y1 = merkle_damgard(H0, X1)
    print(Y.hex())
    print(Y1.hex())
    assert Y == Y1
