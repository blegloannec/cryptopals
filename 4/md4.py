#!/usr/bin/env python3

msk32 = (1<<32)-1
rot = lambda n,r: (n>>(32-r)) | ((n<<r)&msk32)  # int32 left rotate

# https://datatracker.ietf.org/doc/html/rfc1186

def pad(M: bytearray):
    ml = 8*len(M)
    M.append(1<<7)
    k = (-ml-8-64) % 512
    M.extend(0 for _ in range(k//8))
    M.extend(ml.to_bytes(8, 'little'))

def md4(M: bytes, H0=None, do_pad=True) -> bytes:
    # Initialize variables
    if H0 is None:
        # standard values
        H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    elif isinstance(H0, list):
        assert len(H0)==4
        H = H0.copy()
    else:
        assert isinstance(H0, bytes)
        assert 8*len(H0)==128
        H = [int.from_bytes(H0[i:i+4], 'little') for i in range(0, len(H0), 4)]

    M = bytearray(M)
    if do_pad:
        pad(M)
    else:
        assert (8*len(M))%512==0

    F1 = lambda x,y,z: (x & y) | (~x & z)
    S1 = (3,7,11,19)

    F2 = lambda x,y,z: (x & y) | (x & z) | (y & z)
    S2 = (3,5,9,13)
    J2 = (0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15)

    F3 = lambda x,y,z: x ^ y ^ z
    S3 = (3,9,11,15)
    J3 = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15)

    B = [int.from_bytes(M[i:i+4], 'little') for i in range(0, len(M), 4)]
    for b in range(0, len(B), 16):
        X = B[b:b+16]
        A = H.copy()

        for i in range(16):
            A[(0-i)%4] = rot((A[(0-i)%4] + F1(A[(1-i)%4],A[(2-i)%4],A[(3-i)%4]) + X[i]) & msk32, S1[i&3])

        for i in range(16):
            A[(0-i)%4] = rot((A[(0-i)%4] + F2(A[(1-i)%4],A[(2-i)%4],A[(3-i)%4]) + X[J2[i]] + 0x5A827999) & msk32, S2[i&3])

        for i in range(16):
            A[(0-i)%4] = rot((A[(0-i)%4] + F3(A[(1-i)%4],A[(2-i)%4],A[(3-i)%4]) + X[J3[i]] + 0x6ED9EBA1) & msk32, S3[i&3])

        for i in range(4):
            H[i] = (H[i] + A[i]) & msk32

    return b''.join(h.to_bytes(4, 'little') for h in H)


if __name__=='__main__':
    import os, hashlib
    assert 'md4' in hashlib.algorithms_available
    mess = os.urandom(500)
    h0 = md4(mess)
    print(h0.hex())
    ossl_md4 = hashlib.new('md4')
    ossl_md4.update(mess)
    h1 = ossl_md4.digest()
    print(h1.hex())
    assert h0 == h1
