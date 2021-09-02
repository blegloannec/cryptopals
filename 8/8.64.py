#!/usr/bin/env python3

import os, gcm, poly2
import os.path, pickle
from matrix2 import *


## Parameters
bs = poly2._K    # 128 bits
BS = bs>>3       # 16 bytes
msk = (1<<bs)-1
n = 9            # /!\ TODO 9->17 for 8->16 bits
fdata = '64_data.pickle'


## SECRET DATA
_key   = os.urandom(16)
_nonce = os.urandom(12)
_msg   = os.urandom(1<<(n+4))
_h, _  = gcm.get_h_s(_key, _nonce)
##


## == truncated MAC GCM == ##
def truncated_GCM_encrypt(key, nonce, msg):
    ciph, mac = gcm.AES_GCM_encrypt(key, nonce, msg)
    return (ciph, mac[:2])  # /!\ TODO 2->4  # 32-bit truncated MAC

# decrypt is the same
truncated_GCM_decrypt = gcm.AES_GCM_decrypt

def oracle(ciph_mac):
    try:
        truncated_GCM_decrypt(_key, _nonce, ciph_mac)
    except AssertionError:
        return False
    return True


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
    A = cmatrix(bs, bs, [0]*bs)
    for i,di in enumerate(D):
        if di:
            Rc = gen_Rc(di)
            A = c_add(A, rcc_mul(Rc, Cp[i+1]))
    A = cr_swap(A)
    return A

def gen_T():
    T = []
    for i in range(n):
        print(i, end=', ', flush=True)
        for b in range(bs):
            D = [0]*n
            D[i] |= 1<<b
            A = gen_Ad(D)
            c = 0
            for j in range(n-1):
                c |= A.M[j]<<(j*bs)
            T.append(c)
    T = cmatrix((n-1)*bs, n*bs, T)
    T = cr_swap(T)
    return T

def randvec(V):
    u = 0
    for v in V:
        if os.urandom(1)[0]&1:
            u ^= v
    return u

def alter_msg(msg, v):
    C = [gcm.bytes_to_poly(msg[i:i+BS]) for i in reversed(range(0, len(msg), BS))]
    for i in range(1, n+1):
        di = (v>>((i-1)*bs)) & msk
        C[(1<<i)-2] ^= di
    out = b''.join(gcm.poly_to_bytes(c) for c in reversed(C))
    return out


def sanity_check():
    import secrets
    u = secrets.randbelow(1<<(bs*n))
    ciph1,mac1 = gcm.AES_GCM_encrypt(_key, _nonce, _msg)
    ciph2 = alter_msg(ciph1, u)
    mac2 = gcm._aes_gcm_mac(_key, _nonce, ciph2)
    mac1 = gcm.bytes_to_poly(mac1)
    mac2 = gcm.bytes_to_poly(mac2)
    d = mac1^mac2
    c1 = [gcm.bytes_to_poly(ciph1[i:i+BS]) for i in reversed(range(0, len(ciph1), BS))]
    c2 = [gcm.bytes_to_poly(ciph2[i:i+BS]) for i in reversed(range(0, len(ciph2), BS))]
    c1 = [c1[(1<<i)-2] for i in range(1, n+1)]
    c2 = [c2[(1<<i)-2] for i in range(1, n+1)]
    D = [a^b for a,b in zip(c1,c2)]
    A = gen_Ad(D)
    assert rv_mul(A, _h) == d

def main():
    ciph,mac = ciph_mac = truncated_GCM_encrypt(_key, _nonce, _msg)
    #assert truncated_GCM_decrypt(_key, _nonce, ciph_mac) == _msg
    #assert oracle(ciph_mac)

    sanity_check()

    if os.path.exists(fdata):
        print(f'Loading pre-computed data ({fdata})...', end=' ', flush=True)
        T,N = pickle.load(open(fdata, 'rb'))
    else:
        print('Computing T and N...', end=' ', flush=True)
        T = gen_T()
        N = r_nullspace(T)
        pickle.dump((T,N), open(fdata, 'wb'))
    print('ok.')
    #assert all(m2.rv_mul(T, v)==0 for v in N)

    cnt = 1
    while True:
        print(f'Looking for collision... {cnt}' , end='\r', flush=True)
        u = randvec(N)
        #assert m2.rv_mul(T, u) == 0

        #D = [(u>>(i*bs))&msk for i in range(n)]
        #A = Ad(D)
        #X = m2.rmatrix(10, A.c, A.M[:10])
        #m2.r_print(X)
        
        ciph1 = alter_msg(ciph, u)
        if oracle((ciph1, mac)):
            print(f'Looking for collision... ok ({cnt}).')
            break
        cnt += 1

    # TO BE CONTINUED...

if __name__=='__main__':
    main()
