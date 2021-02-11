#!/usr/bin/env python3

import rsalib
from rsalib import int_to_bytes
import base64, decimal


## DATA
_k, K = rsalib.gen_key(1<<10)
_MSG = int.from_bytes(base64.b64decode(b'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='), 'big')
CIPH = rsalib.encrypt(K, _MSG)

def odd_oracle(x: int):
    return rsalib.decrypt(_k, x) & 1


## Attack
c2 = CIPH                  # = m^e mod n
p2 = rsalib.encrypt(K, 2)  # = 2^e mod n
decimal.getcontext().prec = K.n.bit_length()//3
l, r = decimal.Decimal(0), decimal.Decimal(K.n-1)
d2 = decimal.Decimal(2)
for _ in range(K.n.bit_length()):
    c2 = (p2*c2) % K.n
    # let d(i) = decrypted c2(i)
    #          = (2^i * msg) mod n
    # if 2*d(i) < n, d(i) = 2*d(i-1)     even
    # if 2*d(i) >=n, d(i) = 2*d(i-1) - n odd
    # as n is odd (and not prime as the statement says...)
    if odd_oracle(c2):
        l = (l+r)/d2
    else:
        r = (l+r)/d2
msg = int(r)
assert msg == _MSG
print(int_to_bytes(msg))
