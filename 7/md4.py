#!/usr/bin/env python3

# https://datatracker.ietf.org/doc/html/rfc1186
# we rewrite 4/md4.py to fit the notation of Wang et al.
# https://www.iacr.org/archive/eurocrypt2005/34940001/34940001.pdf

msk32 = (1<<32)-1
lrot = lambda n,r: (n>>(32-r)) | ((n<<r)&msk32)       # int32 left  rotate
rrot = lambda n,r: (n>>r) | ((n&((1<<r)-1))<<(32-r))  # int32 right rotate
bytes_to_ints32 = lambda B: [int.from_bytes(B[i:i+4], 'little') for i in range(0, len(B), 4)]
ints32_to_bytes = lambda I: b''.join(i.to_bytes(4, 'little') for i in I)

H0 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
F = lambda x,y,z: (x & y) | (~x & z)
G = lambda x,y,z: (x & y) | (x & z) | (y & z)
H = lambda x,y,z: x ^ y ^ z
J2 = (0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15)
J3 = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15)

def pad(M):
    l = len(M)
    k = (-l-1-8) % 64
    return M + b'\x80' + b'\x00'*k + (8*l).to_bytes(8, 'little')

def compress(aa,bb,cc,dd, X):
    #assert len(X) == 16
    a,b,c,d = aa,bb,cc,dd

    for i in range(0, 16, 4):
        a = lrot((a + F(b,c,d) + X[i])   & msk32, 3)
        d = lrot((d + F(a,b,c) + X[i+1]) & msk32, 7)
        c = lrot((c + F(d,a,b) + X[i+2]) & msk32, 11)
        b = lrot((b + F(c,d,a) + X[i+3]) & msk32, 19)

    for i in range(0, 16, 4):
        a = lrot((a + G(b,c,d) + X[J2[i]]   + 0x5a827999) & msk32, 3)
        d = lrot((d + G(a,b,c) + X[J2[i+1]] + 0x5a827999) & msk32, 5)
        c = lrot((c + G(d,a,b) + X[J2[i+2]] + 0x5a827999) & msk32, 9)
        b = lrot((b + G(c,d,a) + X[J2[i+3]] + 0x5a827999) & msk32, 13)

    for i in range(0, 16, 4):
        a = lrot((a + H(b,c,d) + X[J3[i]]   + 0x6ed9eba1) & msk32, 3)
        d = lrot((d + H(a,b,c) + X[J3[i+1]] + 0x6ed9eba1) & msk32, 9)
        c = lrot((c + H(d,a,b) + X[J3[i+2]] + 0x6ed9eba1) & msk32, 11)
        b = lrot((b + H(c,d,a) + X[J3[i+3]] + 0x6ed9eba1) & msk32, 15)

    aa = (aa + a) & msk32
    bb = (bb + b) & msk32
    cc = (cc + c) & msk32
    dd = (dd + d) & msk32
    return (aa,bb,cc,dd)

def md4(M: bytes) -> bytes:
    aa,bb,cc,dd = H0
    B = bytes_to_ints32(pad(M))
    for b in range(0, len(B), 16):
        X = B[b:b+16]
        aa,bb,cc,dd = compress(aa,bb,cc,dd, X)
    return ints32_to_bytes((aa,bb,cc,dd))


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
