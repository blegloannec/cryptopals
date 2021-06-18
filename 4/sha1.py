#!/usr/bin/env python3

import sys

msk32 = (1<<32)-1
rot = lambda n,r: (n>>(32-r)) | ((n<<r)&msk32)

# https://en.wikipedia.org/wiki/SHA-1

# Note 1: All variables are unsigned 32-bit quantities and wrap modulo 2^32.
# Note 2: All constants in this pseudo code are in big endian.

def pad(M: bytearray):
    ml = 8*len(M)
    M.append(1<<7)
    k = (-ml-8-64) % 512
    M.extend(0 for _ in range(k//8))
    M.extend(ml.to_bytes(8, 'big'))

def sha1(M: bytes, H0=None, do_pad=True) -> bytes:
    # Initialize variables
    if H0 is None:
        # standard values
        H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    elif isinstance(H0, list):
        assert len(H0)==5
        H = H0.copy()
    else:
        assert isinstance(H0, bytes)
        assert 8*len(H0)==160
        H = [int.from_bytes(H0[i:i+4], 'big') for i in range(0, len(H0), 4)]

    # Pre-processing
    # append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
    # append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
    #    is congruent to −64 ≡ 448 (mod 512)
    # append ml, the original message length in bits, as a 64-bit big-endian integer. 
    #    Thus, the total length is a multiple of 512 bits.
    M = bytearray(M)
    if do_pad:
        pad(M)
    else:
        assert (8*len(M))%512==0

    B = [int.from_bytes(M[i:i+4], 'big') for i in range(0, len(M), 4)]
    # Process the message in successive 512-bit chunks
    for b in range(0, len(B), 16):
        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        W = B[b:b+16] + [0]*64

        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words
        for i in range(16, 80):
            # Note 3: SHA-0 differs by not having this leftrotate.
            W[i] = rot(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1)

        # Initialize hash value for this chunk
        a,b,c,d,e = H

        # Main loop
        for i in range(80):
            if i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            tmp = (rot(a, 5) + f + e + k + W[i]) & msk32
            e = d
            d = c
            c = rot(b, 30)
            b = a
            a = tmp

        # Add this chunk's hash to result so far
        for i,x in enumerate((a,b,c,d,e)):
            H[i] = (H[i] + x) & msk32

    # Produce the final hash value (big-endian) as a 160-bit number
    return b''.join(h.to_bytes(4, 'big') for h in H)


if __name__=='__main__':
    print(sha1(sys.stdin.buffer.read()).hex())
