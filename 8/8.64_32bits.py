#!/usr/bin/env python3

import os, secrets
import gcm, poly2
from matrix2 import *
import os.path, pickle


## Parameters
BS = gcm.BS      # 16 bytes
bs = 8*BS        # 128 bits
msk = (1<<bs)-1
n  = 17          # n-1 = 16 rows forced to 0
HS = 4           # 2 bytes = 32 bits hash size
hs = 8*HS

# pre-computed data file (re-computed when missing)
fprecomp = f'64_data_{n}.pickle'


## SECRET DATA
_key   = os.urandom(BS)
_nonce = os.urandom(12)
_msg   = os.urandom((1<<n)*BS)      # 2^n blocks
_h, _  = gcm.get_h_s(_key, _nonce)
##


## == Truncated-MAC GCM == ##
def truncated_GCM_encrypt(key, nonce, msg):
    ciph, mac = gcm.AES_GCM_encrypt(key, nonce, msg)
    return (ciph, mac[:HS])  # truncated MAC

# decrypt is the same (we already allow truncated mac in gcm module)
truncated_GCM_decrypt = gcm.AES_GCM_decrypt

'''
def oracle(ciph_mac):
    try:
        truncated_GCM_decrypt(_key, _nonce, ciph_mac)
    except AssertionError:
        return False
    return True
'''

_poly_h2i = [_h]
for _ in range(n+2):
    _poly_h2i.append(poly2.pmodmul(_poly_h2i[-1], _poly_h2i[-1]))

def fast_oracle(D):
    hmsk = (1<<hs)-1
    d = 0
    for i,di in enumerate(D):
        d ^= poly2.pmodmul(di, _poly_h2i[i+1])
    return d&hmsk == 0


## == Operators matrices == ##
# squaring operator matrix
Cs = cmatrix(bs, bs, [poly2.pmodmul(1<<i, 1<<i) for i in range(bs)])
Rs = cr_swap(Cs)
# powers of 2 (iterated squaring) operators matrices
Cp = [None, Cs]
Rp = [None, Rs]
for _ in range(n+2):
    Cp.append(rcc_mul(Rs, Cp[-1]))
    Rp.append(cr_swap(Cp[-1]))

# constant mul operator matrix
def gen_Rc(c):
    Cc = cmatrix(bs, bs, [poly2.pmodmul(c, 1<<i) for i in range(bs)])
    Rc = cr_swap(Cc)
    return Rc

def gen_Ad(D):
    # D = [d1, ..., dn]
    A = cmatrix(bs, bs)
    for i,di in enumerate(D):
        if di:
            Rc = gen_Rc(di)
            A = c_add(A, rcc_mul(Rc, Cp[i+1]))
    A = cr_swap(A)
    return A

def gen_canonical_Ad(print_progress=True):
    CanonicalAd = []
    for i in range(n):
        if print_progress:
            print(i, end=', ', flush=True)
        for b in range(bs):
            D = [0]*n
            D[i] |= 1<<b
            A = gen_Ad(D)
            CanonicalAd.append(A)
    return CanonicalAd

def gen_T(CanonicalAd, row_cnt=n-1):
    # row_cnt: number of rows of Ad to stuff in T (to force to 0)
    #          n-1 by default
    #          but gets augmented in the accelerated attack
    #assert CanonicalAd[0].r == bs
    cs = CanonicalAd[0].c  # can be < bs in the accelerated attack
    T = []
    for Ad in CanonicalAd:
        c = 0
        for j in range(row_cnt):
            c |= Ad.M[j]<<(j*cs)
        T.append(c)
    T = cmatrix(row_cnt*cs, n*bs, T)
    T = cr_swap(T)
    return T

def randvec(V):
    pick = secrets.randbelow(1<<len(V))
    u = 0
    for i,v in enumerate(V):
        if pick&(1<<i):
            u ^= v
    return u

'''
def alter_msg(msg, v):
    C = [gcm.bytes_to_poly(msg[i:i+BS]) for i in reversed(range(0, len(msg), BS))]
    for i in range(1, n+1):
        di = (v>>((i-1)*bs)) & msk
        C[(1<<i)-2] ^= di
    out = b''.join(gcm.poly_to_bytes(c) for c in reversed(C))
    return out


## Sanity check
def sanity_check():
    u = secrets.randbelow(1<<(n*bs))
    ciph1,mac1 = gcm.AES_GCM_encrypt(_key, _nonce, _msg)
    ciph2 = alter_msg(ciph1, u)
    mac2 = gcm._aes_gcm_mac(_key, _nonce, ciph2)
    mac1 = gcm.bytes_to_poly(mac1)
    mac2 = gcm.bytes_to_poly(mac2)
    d = mac1^mac2
    C1 = [gcm.bytes_to_poly(ciph1[i:i+BS]) for i in reversed(range(0, len(ciph1), BS))]
    C2 = [gcm.bytes_to_poly(ciph2[i:i+BS]) for i in reversed(range(0, len(ciph2), BS))]
    D1 = [C1[(1<<i)-2] for i in range(1, n+1)]
    D2 = [C2[(1<<i)-2] for i in range(1, n+1)]
    D = [a^b for a,b in zip(D1,D2)]
    A = gen_Ad(D)
    assert rv_mul(A, _h) == d
'''

## == Attacks == ##
def basic_attack(ciph, mac):
    K = []
    while len(K) < bs-1:
        print(f'|K| = {len(K)}')
        cnt = 1
        while True:
            print(f'Looking for collision... {cnt}' , end='\r', flush=True)
            u = randvec(NT)
            #ciph1 = alter_msg(ciph, u)
            D = [(u>>(i*bs))&msk for i in range(n)]
            if fast_oracle(D):
                print(f'Looking for collision... ok ({cnt}).')
                break
            cnt += 1
        A = gen_Ad(D)
        K += A.M[n-1:hs]  # non-zero lines corresponding to the truncated hash
        if len(K) >= bs-1:
            # reducing K to a free set of vectors
            print('Checking independance...')
            K = rmatrix(len(K), bs, K)
            rank,K,_ = r_gauss(K)
            K = K.M[:rank]
    K = rmatrix(len(K), bs, K)
    N = r_nullspace(K)
    assert len(N) == 1
    h_ = N[0]
    print(hex(_h))
    print(hex(h_))
    assert h_ == _h


def accelerated_attack(ciph, mac):
    # we truncate to the first hs lines of Ad (hash part) to fasten
    # the update of Ad's (since here we re-do it at each iteration)
    TruncAd = [rmatrix(hs, Ad.c, Ad.M[:hs]) for Ad in CanonicalAd]
    zerows = n-1        # nb of rows forced to 0
    max_zerows = hs-10  # we want at least 10 new vectors
    K = rmatrix(0, bs)
    NewNT = NT
    X = cmatrix(bs, bs)
    while X.c > 1:
        cnt = 1
        print(f'#0-rows = {zerows}, #+vectors = {hs-zerows}, E[iterations] = {1<<(hs-zerows)}')
        while True:
            print(f'Looking for collision... {cnt}' , end='\r', flush=True)
            u = randvec(NewNT)
            D = [(u>>(i*bs))&msk for i in range(n)]
            #ciph1 = alter_msg(ciph, u)
            if fast_oracle(D):
                print(f'Looking for collision... ok ({cnt}).')
                break
            cnt += 1
        A = gen_Ad(D)
        K = rmatrix(K.r+hs-zerows, bs, K.M+A.M[zerows:hs])  # non-zero lines corresponding to the truncated hash
        print("Updating X...")
        X = r_nullspace(K)
        X = cmatrix(bs, len(X), X)
        print(f'dim N(K) = {X.c}')
        # Tradeoff:
        #   the smaller X.c
        #   the bigger we can increase "zerows" the number of rows forced to 0
        #   to reduce the expected number of tries before a collision
        #  BUT
        #   we the smaller number of new vectors for K we get
        #   so we need an upper bound on zerows
        if zerows < max_zerows:
            zerows = min((n-1)*bs // X.c, max_zerows)
            print("Updating canonical Ad's...")
            NewAd = [rcr_mul(Ad, X) for Ad in TruncAd]
            print('Updating T...')
            NewT = gen_T(NewAd, zerows)
            print(f'Updating N(T)...')
            NewNT = r_nullspace(NewT)
    h_ = X.M[0]
    print(hex(_h))
    print(hex(h_))
    assert h_ == _h


## == MAIN == ##
def main():
    global CanonicalAd, T, NT
    ciph,mac = ciph_mac = truncated_GCM_encrypt(_key, _nonce, _msg)
    #assert truncated_GCM_decrypt(_key, _nonce, ciph_mac) == _msg
    #assert oracle(ciph_mac)

    if os.path.exists(fprecomp):
        print(f'Loading pre-computed data ({fprecomp})...', end=' ', flush=True)
        CanonicalAd, T, NT = pickle.load(open(fprecomp, 'rb'))
    else:
        print('Computing T and N...', end=' ', flush=True)
        CanonicalAd = gen_canonical_Ad()
        T = gen_T(CanonicalAd)
        NT = r_nullspace(T)
        pickle.dump((CanonicalAd, T, NT), open(fprecomp, 'wb'))
    print('ok.')

    #basic_attack(ciph, mac)
    accelerated_attack(ciph, mac)


if __name__=='__main__':
    #sanity_check()
    main()
