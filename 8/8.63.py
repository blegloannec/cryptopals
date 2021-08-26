#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from gcm import BS, bytes_to_poly, AES_GCM_encrypt
from poly2 import *
import secrets

def gen_poly(ciph, data, mac):
    data_pad = b'\x00'*((-len(data))%BS)
    ciph_pad = b'\x00'*((-len(ciph))%BS)
    data_siz = (8*len(data)).to_bytes(8, 'big')
    ciph_siz = (8*len(ciph)).to_bytes(8, 'big')
    mash = data + data_pad + ciph + ciph_pad + data_siz + ciph_siz
    # we had mac = ∑ mashᵢ hⁱ⁺¹ + s
    #          s = ∑ mashᵢ hⁱ⁺¹ + mac
    #            = f(h) for f = ∑ mashᵢ Xⁱ⁺¹ + mac
    C = [bytes_to_poly(mac)]
    for i in reversed(range(0, len(mash), BS)):
        b = bytes_to_poly(mash[i:i+BS])
        C.append(b)
    return Poly2k(C)

def attack():
    key   = get_random_bytes(BS)
    nonce = get_random_bytes(12)  # repeated!
    msg1  = get_random_bytes(secrets.randbelow(1<<7))
    data1 = get_random_bytes(secrets.randbelow(1<<7))
    msg2  = get_random_bytes(secrets.randbelow(1<<7))
    data2 = get_random_bytes(secrets.randbelow(1<<7))

    # captured
    ciph1, mac1 = AES_GCM_encrypt(key, nonce, msg1, data1)
    ciph2, mac2 = AES_GCM_encrypt(key, nonce, msg2, data2)

    # secrets to guess (same nonce => same s)
    _h = bytes_to_poly(AES.new(key, AES.MODE_ECB).encrypt(b'\x00'*BS))
    _s = bytes_to_poly(AES.new(key, AES.MODE_ECB).encrypt(nonce + b'\x00\x00\x00\x01'))
    print('Secret:   ', hex(_h), hex(_s))
    found = False

    # attack
    f1 = gen_poly(ciph1, data1, mac1)  # s = f1(h)
    f2 = gen_poly(ciph2, data2, mac2)  # s = f2(h)
    f = f1+f2                          # 0 = (f1+f2)(h)
    for h in f.roots():
        s = f1(h)
        print('Candidate:', hex(h), hex(s))
        if h == _h:
            found = True
    assert found

if __name__=='__main__':
    attack()
