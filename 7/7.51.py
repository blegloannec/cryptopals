#!/usr/bin/env python3

# Reminiscent of the timing attacks of 4.31-32
# NB: Deflate (zlib, gzip) = LZ77 (bytes level) + Huffman (bits level)

import zlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes


_SECRET = b'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
SECSIZE = len(_SECRET)  # assumed known for convenience (as in 4.31-32)
FORM_PREF = b'POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid='
ALPHA = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='

def format_request(P: bytes) -> bytes:
    return FORM_PREF + _SECRET + f'\nContent-Length: {len(P)}\n'.encode() + P

def oracle_stream(P: bytes) -> int:  # using a stream cipher (does not change the size)
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CTR)  # random nonce
    return len(cipher.encrypt(zlib.compress(format_request(P))))

def oracle_cbc(P: bytes) -> int:  # using a CBC cipher (padding after compression!)
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CBC)  # random iv
    return len(cipher.encrypt(pad(zlib.compress(format_request(P)), 16)))


if __name__=='__main__':
    # Attack on the compression + non-padded cipher
    Guess = bytearray()
    for i in range(SECSIZE):
        Guess.append(0)
        cmin = 1<<30
        for a in ALPHA:
            Guess[i] = a
            c = oracle_stream(FORM_PREF + Guess)
            if c<cmin:
                cmin = c; amin = a
        Guess[i] = amin
        print(Guess.decode())
    assert Guess == _SECRET

    # Attack on the compression + padded cipher
    # (sometimes fails, repeat several times if needed)
    Guess = bytearray()
    Suff1 = get_random_bytes(16)
    # we append a random global suffix Suff2 to all our payloads to
    # "stabilize" the results
    Suff2 = get_random_bytes(50)
    for i in range(SECSIZE):
        Guess.append(0)
        cmin = (1<<30, -1<<30)
        for a in ALPHA:
            Guess[i] = a
            P = FORM_PREF + Guess
            c = ck = oracle_cbc(P + Suff2)
            # let us compute the number of random bytes (Suff1)
            # to add to grow by 1 block: the largest it is,
            # the smallest was the original compressed data
            k = 0
            while ck==c:
                k += 1
                ck = oracle_cbc(P + Suff1[:k] + Suff2)
            # we keep the (smallest size, largest #chars to add)
            if (c,-k)<cmin:
                cmin = (c,-k); amin = a
        Guess[i] = amin
        print(Guess.decode())
        assert Guess[i] == _SECRET[i]
    assert Guess == _SECRET
