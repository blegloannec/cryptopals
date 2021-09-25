#!/usr/bin/env python3

import hashlib

def bxor(A,B):
    assert len(A)==len(B)
    return bytes(a^b for a,b in zip(A,B))


## Handmade HMAC - https://en.wikipedia.org/wiki/HMAC
# equivalent to:
#   from Cryptodome.Hash import HMAC, SHA1
#   HMAC.new(K, msg=m, digestmod=SHA1).digest()
# or simply (std lib.):
#   import hmac
#   hmac.new(K, msg=m, digestmod='sha1').digest()

def HMAC_SHA1(K: bytes, m: bytes) -> bytes:
    H = lambda x: hashlib.sha1(x).digest()
    BS = 64  # 512 bits = 64 bytes
    if len(K)>BS:
        K = H(K)
    K += bytes(BS-len(K))
    opad = b'\x5c'*BS
    ipad = b'\x36'*BS
    return H(bxor(K,opad) + H(bxor(K,ipad) + m))


## Sanity check
if __name__=='__main__':
    import os, hmac
    k = os.urandom(16)
    m = os.urandom(500)
    h0 = hmac.new(k, msg=m, digestmod='sha1').digest()
    h1 = HMAC_SHA1(k, m)
    assert h0==h1
