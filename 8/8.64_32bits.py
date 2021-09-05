#!/usr/bin/env python3

'''
This code is based on 8.64.py with some modifications to allow
a fast attack on a 32-bit hash with a message of size 2^17.

Because 2^17 is large, the naive calls to the oracle are slow.
In this version, they have been replaced by a fast simulated oracle
that simply checks that the first 32 bits of ∑ dj h^(2^j) = 0.

In this version, we do not need to bother with the message/ciphertext/MAC
anymore... 
'''

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
hmsk = (1<<hs)-1


# pre-computed data file (re-computed when missing)
fprecomp = f'64_data_{n}.pickle'


## SECRET DATA
_key   = os.urandom(BS)
_nonce = os.urandom(12)
#_msg   = os.urandom((1<<n)*BS)      # 2^n blocks (=> NO PADDING)
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
    d = 0
    for i,di in enumerate(D):
        d ^= poly2.pmodmul(di, _poly_h2i[i+1])
    return d&hmsk == 0


## == Operators matrices == ##
# In GF(2^128) seen as a GF(2) vector space of dimension 128,
# the maps x -> cst*x and x -> x² are linear (trivial & Frobenius morphism).
# They can be represented by the following 128x128 matrices.

# squaring operator matrix
Cs = cmatrix(bs, bs, [poly2.pmodmul(1<<i, 1<<i) for i in range(bs)])
Rs = cr_swap(Cs)
# powers of 2 (iterated squaring) operators matrices
Cp = [None, Cs]
Rp = [None, Rs]
for _ in range(n+2):
    Cp.append(rcc_mul(Rs, Cp[-1]))
    Rp.append(cr_swap(Cp[-1]))

# constant mult. operator matrix
def gen_Rc(c):
    Cc = cmatrix(bs, bs, [poly2.pmodmul(c, 1<<i) for i in range(bs)])
    Rc = cr_swap(Cc)
    return Rc

# Consider the authentication (without add. data) of a ciphertext [ck c(k-1) .. c1]
#   mac = s + c0 h + ∑ ci h^i  for s the auth. mask and c0 the size block
# consider a second ciphertext [c'k c'(k-1) .. c'1], same key (same s), same size (same c0)
#   mac' = s + c0 h + ∑ ci h^i
#   mac'-mac = ∑ (ci-c'i) h^i
# if ciphertexts only differ in some indices i = 2^j, then for dj = c(2^j) - c'(2^j),
#   mac'-mac = ∑ dj h^(2^j)
#            = ∑ Mc(dj) Ms^j h  for Mc(dj) the mult. by dj operator matrix
#                                   and Ms     the squaring operator matrix
#            = (∑ Mc(dj) Ms^j) h
# let Ad = ∑ Mc(dj) Ms^j
# truncated MAC collision:
#   the first hs bits of mac'-mac = 0  <=>  the first hs bits of Ad h = 0
def gen_Ad(D):
    # D = [d1, ..., dn]
    A = cmatrix(bs, bs)
    for i,di in enumerate(D):
        if di:
            Rc = gen_Rc(di)
            A = c_add(A, rcc_mul(Rc, Cp[i+1]))
    A = cr_swap(A)
    return A

# Considering d = [d1 .. dn] as a vector from a GF(2) vector space
# of dimension 128n, the map d -> Ad (in L(GF(2)^128)) is linear.
# It is perfectly caracterized by [A(e1) .. A(en)]
# for (ei)_i the canonical base of GF(2)^(128n).
# NB: This is completely independent from the parameters,
#     this only depends on the GF(2^128) field we use.
def gen_canonical_A(print_progress=True):
    CanonicalA = []
    for i in range(n):
        if print_progress:
            print(i, end=', ', flush=True)
        for b in range(bs):
            D = [0]*n
            D[i] |= 1<<b
            A = gen_Ad(D)
            CanonicalA.append(A)
    return CanonicalA

# If we can find some d such that the first z lines of Ad are forced
# to 0, then the first z bits of Ad*h will be 0, and there will
# remain hs-z bits to cancel.
# If we can generate randomly enough such vectors d, then we will
# have a 1/(hs-z) chance of collision.
# Let T be the matrix whose 128n columns are the z first lines of
# each of the 128n matrices A(e1) .. A(en).
# We are looking for d such that T*d = 0, i.e. d in ker T.
# NB: T only depends on the GF(2^128) field we use (and z).
# For k = dim ker T, we get 2^k candidates to pick randomly for d.
# We want this to be large enough compared to 2^(hs-z).
# T is of size 128k × 128n with k ≤ n.
# If we choose z = n, then T is square and is likely to have a
# very small ker (while we need k >> hs-z).
# Choosing z = n-1, we are sure that k ≥ 128 and we will
# always have more than enough candidates.
def gen_T(CanonicalA, zerows=n-1):
    # zerows: number of rows of Ad to stuff in T (to force to 0)
    #         n-1 by default
    #         but gets augmented in the accelerated attack
    #assert CanonicalAd[0].r == bs
    cs = CanonicalA[0].c  # can be < bs in the accelerated attack
    T = []
    for Aei in CanonicalA:
        c = 0
        for j in range(zerows):
            c |= Aei.M[j]<<(j*cs)
        T.append(c)
    T = cmatrix(zerows*cs, n*bs, T)
    T = cr_swap(T)
    return T


# picks a random vector given a generating set
def randvec(V):
    pick = secrets.randbelow(1<<len(V))
    u = 0
    for i,v in enumerate(V):
        if pick&(1<<i):
            u ^= v
    return u

'''
# alter message according to given d
def alter_msg(msg, d):
    C = [gcm.bytes_to_poly(msg[i:i+BS]) for i in reversed(range(0, len(msg), BS))]
    for i in range(1, n+1):
        di = (d>>((i-1)*bs)) & msk
        C[(1<<i)-2] ^= di
    out = b''.join(gcm.poly_to_bytes(c) for c in reversed(C))
    return out
'''


## == Attacks == ##
def basic_attack():
    # In the basic attack, at each collision found, we
    # add hs-(n-1) non-zero vectors to a matrix K such that K*h = 0
    # until K is of rank 127, in which case dim ker K = 1,
    # and ker K is generated by h.
    K = rmatrix(0, bs)
    while K.r < bs-1:
        print(f'|K| = {K.r}')
        cnt = 1
        while True:
            print(f'Looking for collision... {cnt}' , end='\r', flush=True)
            d = randvec(NT)
            D = [(d>>(i*bs))&msk for i in range(n)]
            if fast_oracle(D):
                print(f'Looking for collision... ok ({cnt}).')
                break
            cnt += 1
        A = gen_Ad(D)
        K = r_extend(K, A.M[n-1:hs])  # non-zero lines corresponding to the truncated hash
        if K.r >= bs-1:
            # reducing K to a free set of vectors
            print('Checking independance...')
            rank,K,_ = r_gauss(K)
            K = r_trunc(K, rank)
    N = r_nullspace(K)
    assert len(N) == 1
    h_ = N[0]
    print(hex(_h))
    print(hex(h_))
    assert h_ == _h

def accelerated_attack():
    # In the accelerated attack, we use the current K to improve our chances
    # of finding a collision.
    # For X = ker K of size 128×k for k = dim ker K,
    # we know there exists h' in GF(2)^k such that h = X h'.
    # But then Ad h = 0 becomes Ad' h' = 0 with A'd = Ad X of size 128×k.
    # Let T' be the same as T but for A'. T' is of size k*z × 128n,
    # with initially k = 128 and z = n-1, but as k decreases along the
    # attack, we can reasonably increase z to improve our chances of collision.
    # NB: We truncate to the first hs lines of A (hash part) to fasten
    #     the update of A(ei)'s (since here we re-do it at each iteration).
    TruncA = [r_trunc(Aei, hs) for Aei in CanonicalA]
    zerows = n-1        # nb of rows forced to 0
    max_zerows = hs-10  # we want at least 10 new vectors
    K = rmatrix(0, bs)
    NewNT = NT
    X = cmatrix(bs, bs)
    while X.c > 1:
        cnt = 1
        print(f'#0ws = {zerows}, #+vec = {hs-zerows}, E[iter] = {1<<(hs-zerows)}')
        while True:
            print(f'Looking for collision... {cnt}' , end='\r', flush=True)
            d = randvec(NewNT)
            D = [(d>>(i*bs))&msk for i in range(n)]
            if fast_oracle(D):
                print(f'Looking for collision... ok ({cnt}).')
                break
            cnt += 1
        A = gen_Ad(D)
        K = r_extend(K, A.M[zerows:hs])  # non-zero lines corresponding to the truncated hash
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
            print("Updating canonical A(ei)'s...")
            NewA = [rcr_mul(Aei, X) for Aei in TruncA]
            print('Updating T...')
            NewT = gen_T(NewA, zerows)
            print(f'Updating N(T)...')
            NewNT = r_nullspace(NewT)
    h_ = X.M[0]
    print(hex(_h))
    print(hex(h_))
    assert h_ == _h


## == MAIN == ##
def main():
    global CanonicalA, T, NT
    #ciph,mac = ciph_mac = truncated_GCM_encrypt(_key, _nonce, _msg)

    if os.path.exists(fprecomp):
        print(f'Loading pre-computed data ({fprecomp})...', end=' ', flush=True)
        CanonicalA, T, NT = pickle.load(open(fprecomp, 'rb'))
    else:
        print('Computing T and N(T)...', end=' ', flush=True)
        CanonicalA = gen_canonical_A()
        T = gen_T(CanonicalA)
        NT = r_nullspace(T)
        pickle.dump((CanonicalA, T, NT), open(fprecomp, 'wb'))
    print('ok.')

    #basic_attack()
    accelerated_attack()


if __name__=='__main__':
    main()
