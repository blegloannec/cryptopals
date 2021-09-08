#!/usr/bin/env python3

import os, secrets
import gcm, poly2
from matrix2 import *
import os.path, pickle


## Parameters
BS = gcm.BS      # 16 bytes
bs = 8*BS        # 128 bits

n  = 9           # n-1 = 8 rows forced to 0
HS = 2           # 2 bytes = 16 bits hash size
hs = 8*HS

# pre-computed data file (re-computed when missing)
fprecomp = f'64_data_{n}.pickle'


## SECRET DATA
_key   = os.urandom(BS)
_nonce = os.urandom(12)
_msg   = os.urandom((1<<n)*BS)      # 2^n blocks (=> NO PADDING)
_h, _  = gcm.get_h_s(_key, _nonce)
##


## == Truncated-MAC GCM == ##
def truncated_GCM_encrypt(key, nonce, msg):
    ciph, mac = gcm.AES_GCM_encrypt(key, nonce, msg)
    return (ciph, mac[:HS])  # truncated MAC

# decrypt is the same (we already allow truncated mac in gcm module)
truncated_GCM_decrypt = gcm.AES_GCM_decrypt

def oracle(ciph_mac):
    try:
        truncated_GCM_decrypt(_key, _nonce, ciph_mac)
    except gcm.InvalidMAC:
        return False
    return True


## == Operators matrices == ##
# In GF(2^128) seen as a GF(2) vector space of dimension 128,
# the maps x -> cst*x and x -> x² are linear (trivial & Frobenius morphism).
# They can be represented by the following 128x128 matrices.

# squaring operator matrix
CMsqr = cmatrix(bs, bs, [poly2.pmodmul(1<<i, 1<<i) for i in range(bs)])
RMsqr = cr_swap(CMsqr)
# powers of 2 (iterated squaring) operators matrices
CMpow2 = [None, CMsqr]
for _ in range(n):
    CMpow2.append(rcc_mul(RMsqr, CMpow2[-1]))

# constant mult. operator matrix
def gen_RMcst(c):
    CMcst = cmatrix(bs, bs, [poly2.pmodmul(c, 1<<i) for i in range(bs)])
    RMcst = cr_swap(CMcst)
    return RMcst

# Consider the authentication (without add. data) of a ciphertext [ck c(k-1) .. c1]
#   mac = s + c0 h + ∑ ci h^i  for s the auth. mask and c0 the size block
# consider a second ciphertext [c'k c'(k-1) .. c'1], same key (same s), same size (same c0)
#   mac' = s + c0 h + ∑ c'i h^i
#   mac'-mac = ∑_{i>1} (c'i-ci) h^i
# if ciphertexts only differ in some indices i = 2^j > 1, then for dj = c'(2^j)-c(2^j),
#   mac'-mac = ∑_{j>0} dj h^(2^j)
#            = ∑ Mc(dj) Ms^j h  for Mc(dj) the mult. by dj operator matrix
#                               and Ms the squaring operator matrix
#            = (∑ Mc(dj) Ms^j) h
# let Ad = ∑ Mc(dj) Ms^j
# truncated MAC collision:
#   the first hs bits of mac'-mac = 0  <=>  the first hs bits of Ad h = 0

def enum_d(d):
    # d in {0,1}^128n -> [d1 .. dn] with di in {0,1}^128
    msk = (1<<bs)-1
    for i in range(n):
        di = (d>>(i*bs)) & msk
        yield (i+1, di)

def gen_A(d):
    A = cmatrix(bs, bs)
    for i,di in enum_d(d):
        if di:
            RMdi = gen_RMcst(di)
            A = c_add(A, rcc_mul(RMdi, CMpow2[i]))
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
    for i in range(n*bs):
        if print_progress and i%bs == 0:
            print(i//bs, end=', ', flush=True)
        A = gen_A(1<<i)
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

# alter message according to given d
def alter_msg(msg, d):
    C = [gcm.bytes_to_poly(msg[i:i+BS]) for i in reversed(range(0, len(msg), BS))]
    for i,di in enum_d(d):
        C[(1<<i)-2] ^= di
    out = b''.join(gcm.poly_to_bytes(c) for c in reversed(C))
    return out


## Sanity check
def sanity_check():
    d = secrets.randbelow(1<<(n*bs))
    ciph1,mac1 = gcm.AES_GCM_encrypt(_key, _nonce, _msg)
    ciph2 = alter_msg(ciph1, d)
    mac2 = gcm._aes_gcm_mac(_key, _nonce, ciph2)
    mac1 = gcm.bytes_to_poly(mac1)
    mac2 = gcm.bytes_to_poly(mac2)
    dmac = mac1^mac2
    A = gen_A(d)
    assert rv_mul(A, _h) == dmac


## == Attacks == ##
def basic_attack(ciph, mac):
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
            ciph1 = alter_msg(ciph, d)
            if oracle((ciph1, mac)):
                print(f'Looking for collision... ok ({cnt}).')
                break
            cnt += 1
        A = gen_A(d)
        K = r_extend(K, A.M[n-1:hs])  # non-zero lines corresponding to the truncated hash
        if K.r >= bs-1:
            # reducing K to a free set of vectors
            print('Checking independence...')
            rank,K,_ = r_gauss(K)
            K = r_trunc(K, rank)
    N = r_nullspace(K)
    assert len(N) == 1
    h_ = N[0]
    print(hex(_h))
    print(hex(h_))
    assert h_ == _h

def accelerated_attack(ciph, mac):
    # In the accelerated attack, we use the current K to improve our chances
    # of finding a collision.
    # For X a basis of ker K of size 128×k for k = dim ker K,
    # we know there exists h' in GF(2)^k such that h = X h'.
    # But then Ad h = 0 becomes Ad' h' = 0 with A'd = Ad X of size 128×k.
    # Let T' be the same as T but for A'. T' is of size k*z × 128n,
    # with initially k = 128 and z = n-1, but as k decreases along the
    # attack, we can reasonably increase z to improve our chances of collision.
    # NB: We truncate to the first hs lines of A (hash part) to fasten
    #     the update of A(ei)'s (since here we re-do it at each iteration).
    TruncA = [r_trunc(Aei, hs) for Aei in CanonicalA]
    zerows = n-1       # nb of rows forced to 0
    max_zerows = hs-5  # we want at least 5 new vectors
    K = rmatrix(0, bs)
    NewNT = NT
    X = cmatrix(bs, bs)
    while X.c > 1:
        cnt = 1
        print(f'#0ws = {zerows}, #+vec = {hs-zerows}, E[iter] = {1<<(hs-zerows)}')
        while True:
            print(f'Looking for collision... {cnt}' , end='\r', flush=True)
            d = randvec(NewNT)
            ciph1 = alter_msg(ciph, d)
            if oracle((ciph1, mac)):
                print(f'Looking for collision... ok ({cnt}).')
                break
            cnt += 1
        print('Updating K...')
        A = gen_A(d)
        K = r_extend(K, A.M[zerows:hs])  # non-zero lines corresponding to the truncated hash
        print('Updating X = N(K)...')
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
    ciph,mac = ciph_mac = truncated_GCM_encrypt(_key, _nonce, _msg)
    #assert truncated_GCM_decrypt(_key, _nonce, ciph_mac) == _msg
    #assert oracle(ciph_mac)

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

    #basic_attack(ciph, mac)
    accelerated_attack(ciph, mac)


if __name__=='__main__':
    #sanity_check()
    main()
