#!/usr/bin/env python3

# We use the second suggested approach here for SHA1 (160 bits) / RSA-1024.
# The first approach is described here (for SHA1 / RSA-3072):
# https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
# The attack is easier with:
#  - small hashes
#  - large keys
# since we need 3*(hash size + const.) < key size

import rsalib, re
from rsalib import int_to_bytes
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes

ASN1 = b'ASN.1_ID_DATA'  # used to identify the algorithms used

def pkcs115_pad(bit_length: int, h: bytes) -> bytes:
    cnt = bit_length//8 - len(ASN1) - len(h) - 3
    return b'\x00\x01' + b'\xff'*cnt + b'\x00' + ASN1 + h

def rsa_sign(k, h: bytes) -> bytes:
    ph = pkcs115_pad(k.n.bit_length()-1, h)
    return int_to_bytes(rsalib.encrypt(k, int.from_bytes(ph, 'big')))

def rsa_verify(K, h: bytes, sig: bytes) -> bool:
    # NB: our int_to_bytes() does not output leading 0s (so we prepend 1)
    h1 = b'\x00' + int_to_bytes(rsalib.decrypt(K, int.from_bytes(sig, 'big')))
    print('Decrypted hash:', h1)
    # bad verif.: we only check a prefix of the decrypted data
    pref = b'\x00\x01\xff*\x00' + re.escape(ASN1 + h)
    return re.match(pref, h1) is not None

# forge a fake signature
def forge_sig(K, h: bytes) -> bytes:
    assert K.e == 3
    s = b'\x00\x01\xff\x00' + ASN1 + h
    # we triple the size of the signature by padding with garbage
    s += get_random_bytes(2*(len(s)+1))
    # we take an approx. integer cube root (as s is not likely a perfect cube)
    r = rsalib.root3(int.from_bytes(s, 'big'))
    # r^3 does not reach the modulus
    assert r**3 <= K.n
    # its bits will start with the target signature
    return int_to_bytes(r)

if __name__=='__main__':
    msg = b'hi mom'
    h = SHA1.new(msg).digest()
    k, K = rsalib.gen_key(1<<10)  # 1024-bit RSA
    sig = rsa_sign(k, h)
    assert rsa_verify(K, h, sig)
    print()
    sig = forge_sig(K, h)
    assert rsa_verify(K, h, sig)
