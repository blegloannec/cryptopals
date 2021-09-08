#!/usr/bin/env python3

import os, secrets
import gcm, poly2
from matrix2 import *
import os.path, pickle


## Parameters
BS = gcm.BS      # 16 bytes
bs = 8*BS        # 128 bits

n  = 8           # 8 rows forced to 0
HS = 2           # 2 bytes = 16 bits hash size
hs = 8*HS

# pre-computed data file (re-computed when missing)
fprecomp = f'65_data_{n}.pickle'


## SECRET DATA
_key   = os.urandom(BS)
_h, _  = gcm.get_h_s(_key)
##


## == Truncated-MAC GCM == ##
def truncated_GCM_encrypt(key, nonce, msg):
    ciph, mac = gcm.AES_GCM_encrypt(key, nonce, msg)
    return (ciph, mac[:HS])  # truncated MAC

# decrypt is the same (we already allow truncated mac in gcm module)
truncated_GCM_decrypt = gcm.AES_GCM_decrypt

def oracle(nonce, ciph, mac):
    try:
        truncated_GCM_decrypt(_key, nonce, (ciph, mac))
    except gcm.InvalidMAC:
        return False
    return True

def capture_msg():
    nonce = os.urandom(12)
    msg = os.urandom(secrets.randbelow((1<<n)*BS))
    ciph, mac = truncated_GCM_encrypt(_key, nonce, msg)
    return (nonce, ciph, mac)


## == Operators matrices == ##

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


# Consider the authentication of a padded ciphertext [ck c(k-1) .. c1]
# with c0 the size block containing the unpadded size:
#   mac = s + c0 h + ∑ ci h^i
# consider a second ciphertext [c'k c'(k-1) .. c'1], same key (same s)
# but with an altered size block c'0 containing the padded size (as if the
# padding was part of the ciphertext):
#   mac' = s + c'0 h + ∑ c'i h^i
#   mac'-mac = (c'0-c0) h + ∑_{i>0} (ci-c'i) h^i
# if ciphertexts only differ in some indices i = 2^j, then for dj = c'(2^j)-c(2^j),
#   mac'-mac = d0 h^(2^0) + ∑_{j>0} dj h^(2^j)
#            = Mc(d0) h + ∑ Mc(dj) Ms^j h  for Mc(dj) the mult. by dj operator matrix
#                                          and Ms the squaring operator matrix
#            = (Mc(d0) + ∑ Mc(dj) Ms^j) h
# let Ad = ∑ Mc(dj) Ms^j and B = Mc(d0) which only depends on the size
#            = (B + Ad) h
# truncated MAC collision:
#   the first hs bits of mac'-mac = 0  <=>  the first hs bits of Ad h = B h

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

def gen_canonical_A(print_progress=True):
    CanonicalA = []
    for i in range(n*bs):
        if print_progress and i%bs == 0:
            print(i//bs, end=', ', flush=True)
        A = gen_A(1<<i)
        CanonicalA.append(A)
    return CanonicalA

# If we can find some d such that the first z lines of Ad are forced
# to those of B, then the first z bits of (B+Ad)*h will be 0, and there will
# remain hs-z bits to cancel.
# Let T be the matrix whose 128n columns are the z first lines of
# each of the 128n matrices A(e1) .. A(en).
# Let b be the 128n-bit vector of the lines of B.
# We are looking for d such that T*d = b.

# In 8.64, we had b = 0, d in ker T and were choosing z < n
# to make sure dim ker T > 0 (otherwise the only solution
# if 0).
# Here, having b ≠ 0, if we choose z = n, then T is square and
# is actually invertible, but a = T^(-1) b ≠ 0 and we
# can try a as an alteration vector that forces n bits to 0
# instead of n-1.
# Of course this does not always work since we only have one vector
# to try but we have a 2^-n chance that it works instead of 2^-(n+1)
# without altering the size.

def gen_T(CanonicalA, zerows=n):
    # zerows: number of rows of Ad to stuff in T (to force to 0)
    #         n by default here (square matrix of dimensions 128n)
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


## == Attacks == ##
def tweak_ciph_length(ciph):
    # current size block
    data_siz = b'\x00'*8
    ciph_siz = (8*len(ciph)).to_bytes(8, 'big')
    c0 = gcm.bytes_to_poly(data_siz + ciph_siz)
    # we pad ciph as it would be by GCM with its current size
    ciph += b'\x00'*((-len(ciph))%BS)
    # this allows to gain a few free bits whenever the last block
    # is incomplete and is a power of 2...
    # but we can do much better as we can prepend blocks of 0
    # (which translate to ci = 0, hence having no impact
    #  on the hash, except for the size change)
    # to make sure we reach 2^n blocks + a random amount
    # to spice it up (technically, we could gain as many bits
    # as we want, but at the cost of making the message size
    # grow exponentially)
    s = (max(1<<n, len(ciph)) + secrets.randbelow(1<<n))*BS
    ciph = b'\x00'*(s-len(ciph)) + ciph
    ciph_siz = (8*len(ciph)).to_bytes(8, 'big')
    cp0 = gcm.bytes_to_poly(data_siz + ciph_siz)
    # size block diff.
    d0 = c0^cp0
    return (ciph, d0)

def get_first_solution(B):
    # given B = Md0, we solve T a = b
    # for b the vector of B's first n lines
    # and T square and invertible of inverse Tinv
    b = 0
    for i in range(n):
        b |= B.M[i]<<(i*bs)
    a = rv_mul(Tinv, b)
    return a

def catch_first_msg():
    # we capture messages until we catch one that is vulnerable
    # to the tweak
    cnt = 1
    prompt = f'Waiting for forgery (E[iter] = {1<<(hs-n)})...'
    while True:
        print(prompt, cnt , end='\r', flush=True)
        nonce, ciph, mac = capture_msg()
        ciph0, d0 = tweak_ciph_length(ciph)
        B = gen_RMcst(d0)
        d = get_first_solution(B)
        ciph1 = alter_msg(ciph0, d)
        if oracle(nonce, ciph1, mac):
            print(prompt, f'ok ({cnt}).')
            break
        cnt += 1
    return (nonce, ciph0, mac, B, d)

def get_solution(T, B, zerows=n):
    # given B = Md0 X, we solve T X a = b
    # for b the vector of B's first n lines
    # T X is not square and not invertible anymore
    # we use a Gauss-based procedure to find a
    # particular solution
    b = 0
    for i in range(zerows):
        b |= B.M[i]<<(i*B.c)
    a = r_system_solve(T, b)
    assert a >= 0
    return a

def attack():
    # For X a basis of ker K of size 128×k for k = dim ker K,
    # we know there exists h' in GF(2)^k such that h = X h'.
    # But then Ad h = B h becomes Ad' h' = B' h with A'd = Ad X
    # and B' = B X of size 128×k.
    # Let T' be the same as T but for A'. T' is of size k*z × 128n,
    # we fall back to solving T' d = b' for b' the first z lines
    # of B'.
    nonce, ciph, mac, B, d = catch_first_msg()
    K = rmatrix(0, bs)

    TruncA = [r_trunc(Aei, hs) for Aei in CanonicalA]
    zerows = n         # nb of rows forced to 0
    max_zerows = hs-4  # we want at least 4 new vectors
    while True:
        print('Updating K...')
        A = gen_A(d)
        A = r_add(A, B)
        K = r_extend(K, A.M[zerows:hs])  # non-zero lines corresponding to the truncated hash
        print('Updating X = N(K)...')
        X = r_nullspace(K)
        X = cmatrix(bs, len(X), X)
        print(f'dim N(K) = {X.c}')
        if X.c == 1:
            break
        zerows = min(n*bs//X.c, max_zerows)
        print("Updating canonical A(ei)'s...")
        NewA = [rcr_mul(Aei, X) for Aei in TruncA]
        print('Updating T...')
        NewT = gen_T(NewA, zerows)
        print(f'Updating N(T)...', end=' ', flush=True)
        NewNT = r_nullspace(NewT)
        print(f'(dim {len(NewNT)})')
        print('Computing a particular solution...')
        BX = rcr_mul(B, X)
        d1 = get_solution(NewT, BX, zerows)

        cnt = 1
        print(f'#0ws = {zerows}, #+vec = {hs-zerows}, E[iter] = {1<<(hs-zerows)}')
        while True:
            print(f'Looking for collision... {cnt}' , end='\r', flush=True)
            d = d1 ^ randvec(NewNT)  # particular solution + null vector
            ciph1 = alter_msg(ciph, d)
            if oracle(nonce, ciph1, mac):
                print(f'Looking for collision... ok ({cnt}).')
                break
            cnt += 1

    h_ = X.M[0]
    print(hex(_h))
    print(hex(h_))
    assert h_ == _h


## == MAIN == ##
def main():
    global CanonicalA, T, Tinv

    if os.path.exists(fprecomp):
        print(f'Loading pre-computed data ({fprecomp})...', end=' ', flush=True)
        CanonicalA, T = pickle.load(open(fprecomp, 'rb'))
    else:
        print('Computing T...', end=' ', flush=True)
        CanonicalA = gen_canonical_A()
        T = gen_T(CanonicalA)
        pickle.dump((CanonicalA, T), open(fprecomp, 'wb'))
    print('ok.')
    Tinv = r_inverse(T)

    attack()


if __name__=='__main__':
    main()
