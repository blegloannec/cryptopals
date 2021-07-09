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
                return (B, Pred[H1][1], H1)
        else:
            Pred[H1] = (B, None)
        H2 = compression(H02, B)
        if H2 in Pred:
            if Pred[H2][0] is not None:
                return (Pred[H2][0], B, H2)
        else:
            Pred[H2] = (None, B)


class StatesTree:
    def __init__(self, k: int):
        # O(2^(k+1) * 2^(8*HS/2))
        self.k = k
        self.N = 1<<self.k
        self.States = [None]*self.N + [get_random_bytes(HS) for _ in range(self.N)]
        self.Blocks = [None]*(2*self.N)
        for i in range(self.N-1, 0, -1):
            self.Blocks[2*i], self.Blocks[2*i+1], self.States[i] = \
                random_collision(self.States[2*i], self.States[2*i+1])
        self.Leaves = {self.States[i]:i for i in range(self.N, 2*self.N)}

    def root(self):
        return self.States[1]

    def path(self, leaf):
        if leaf in self.Leaves:
            i = self.Leaves[leaf]
            Path = []
            while i>1:
                Path.append(self.Blocks[i])
                i >>= 1
            return b''.join(Path)


if __name__=='__main__':
    H0 = get_random_bytes(HS)
    k = 2*HS
    target_size = 20*BS
    print(f'hash size = {HS} bytes, k = {k}')

    print('Pre-computing hash funnel (states tree)...', end=' ', flush=True)
    HF = StatesTree(k)
    print('ok.')

    assert target_size % BS == 0
    pad_suff = md_pad(bytes(target_size))[target_size:]
    prediction = _md(HF.root(), pad_suff)
    print(f'Prediction: {prediction.hex()}')

    arbitrary_msg = get_random_bytes(target_size - (k+1)*BS)  # whatever we want
    H1 = _md(H0, arbitrary_msg)
    print('Randomly looking for a bridge...', end=' ', flush=True)
    # proba:       2^k/2^(8*HS)
    # expected time: 1/proba    = 2^(8*HS-k)
    suff = None
    t = 0
    while suff is None:
        bridge = get_random_bytes(BS)
        H = compression(H1, bridge)
        suff = HF.path(H)
        t += 1
    print(f'ok ({t} tries).')

    M = arbitrary_msg + bridge + suff
    assert len(M) == target_size
    result = merkle_damgard(H0, M)
    print(f'Result: {result.hex()}')
    assert result == prediction
