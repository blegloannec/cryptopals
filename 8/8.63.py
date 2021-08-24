#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from Cryptodome.Random import get_random_bytes
from poly2 import *
import secrets

BS = 16

def rev_int8(x):
    # for bit-level little-endianness
    r = 0
    for i in range(8):
        if (x>>i)&1:
            r |= 1<<(7-i)
    return r

def bytes_to_poly(B):
    assert len(B) == BS
    return int.from_bytes((rev_int8(b) for b in B), 'little')

def poly_to_bytes(p):
    return bytes(rev_int8(b) for b in p.to_bytes(BS, 'little'))

def _aes_gcm_crypt(key, nonce, msg):
    # CTR encryption
    ciph = []
    cntr = 1
    cntr_mask = (1<<32)-1
    for i in range(0, len(msg), BS):
        cntr = (cntr + 1) & cntr_mask
        counter = nonce + cntr.to_bytes(4, 'big')
        C = AES.new(key, AES.MODE_ECB).encrypt(counter)
        M = msg[i:i+BS]
        if len(C) > len(M):
            C = C[:len(M)]
        ciph.append(strxor(C, M))
    ciph = b''.join(ciph)
    return ciph

def _aes_gcm_mac(key, nonce, ciph, data):
    # MAC computation
    data_pad = b'\x00'*((-len(data))%BS)
    ciph_pad = b'\x00'*((-len(ciph))%BS)
    data_siz = (8*len(data)).to_bytes(8, 'big')
    ciph_siz = (8*len(ciph)).to_bytes(8, 'big')
    mash = data + data_pad + ciph + ciph_pad + data_siz + ciph_siz
    h = bytes_to_poly(AES.new(key, AES.MODE_ECB).encrypt(b'\x00'*BS))
    # Horner's computation of ∑ mashᵢ hⁱ⁺¹ where h only depends on the key
    g = 0
    for i in range(0, len(mash), BS):
        b = bytes_to_poly(mash[i:i+BS])
        g = pmodmul(g^b, h)
    # finalize mac = ∑ mashᵢ hⁱ⁺¹ + s where s only depends on the key & nonce
    s = bytes_to_poly(AES.new(key, AES.MODE_ECB).encrypt(nonce + b'\x00\x00\x00\x01'))
    mac = poly_to_bytes(g^s)
    return mac

def AES_GCM_encrypt(key, nonce, msg, data=b''):
    assert len(key)   == BS
    assert len(nonce) == 12  # 96 bits
    ciph = _aes_gcm_crypt(key, nonce, msg)
    mac = _aes_gcm_mac(key, nonce, ciph, data)
    return (ciph, mac)

def AES_GCM_decrypt(key, nonce, ciph_mac, data=b''):
    assert len(key)   == BS
    assert len(nonce) == 12  # 96 bits
    ciph, mac0 = ciph_mac
    mac1 = _aes_gcm_mac(key, nonce, ciph, data)
    assert mac1 == mac0
    msg = _aes_gcm_crypt(key, nonce, ciph)
    return msg


def sanity_check(it=10):
    for _ in range(it):
        key   = get_random_bytes(BS)
        nonce = get_random_bytes(12)
        msg   = get_random_bytes(secrets.randbelow(1<<9))
        data  = get_random_bytes(secrets.randbelow(1<<9))
        ciph0, mac0 = ciph_mac = AES_GCM_encrypt(key, nonce, msg, data)
        C = AES.new(key, AES.MODE_GCM, nonce=nonce)
        C.update(data)
        ciph1, mac1 = C.encrypt_and_digest(msg)
        assert mac0 == mac1 and ciph0 == ciph1
        msg1 = AES_GCM_decrypt(key, nonce, ciph_mac, data)
        assert msg1 == msg


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
    sanity_check()
    attack()
