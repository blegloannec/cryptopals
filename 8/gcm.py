#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from poly2 import *

BS = 16

def _rev_int8(x):
    # for bit-level little-endianness
    r = 0
    for i in range(8):
        if (x>>i)&1:
            r |= 1<<(7-i)
    return r

rev_int8 = tuple(_rev_int8(x) for x in range(1<<8))

def bytes_to_poly(B):
    assert len(B) == BS
    return int.from_bytes((rev_int8[b] for b in B), 'little')

def poly_to_bytes(p):
    return bytes(rev_int8[b] for b in p.to_bytes(BS, 'little'))

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

def get_h_s(key, nonce):
    # auth. "key" and "mask"
    h = bytes_to_poly(AES.new(key, AES.MODE_ECB).encrypt(b'\x00'*BS))
    s = bytes_to_poly(AES.new(key, AES.MODE_ECB).encrypt(nonce + b'\x00\x00\x00\x01'))
    return (h,s)

def _aes_gcm_mac(key, nonce, ciph, data):
    # MAC computation
    data_pad = b'\x00'*((-len(data))%BS)
    ciph_pad = b'\x00'*((-len(ciph))%BS)
    data_siz = (8*len(data)).to_bytes(8, 'big')
    ciph_siz = (8*len(ciph)).to_bytes(8, 'big')
    mash = data + data_pad + ciph + ciph_pad + data_siz + ciph_siz
    h,s = get_h_s(key, nonce)
    # Horner's computation of ∑ mashᵢ hⁱ⁺¹ where h only depends on the key
    g = 0
    for i in range(0, len(mash), BS):
        b = bytes_to_poly(mash[i:i+BS])
        g = pmodmul(g^b, h)
    # finalize mac = ∑ mashᵢ hⁱ⁺¹ + s where s only depends on the key & nonce
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
    assert mac1.startswith(mac0)  # allows truncated MAC
    msg = _aes_gcm_crypt(key, nonce, ciph)
    return msg


# Sanity check
def sanity_check(it=10):
    for _ in range(it):
        key   = os.urandom(BS)
        nonce = os.urandom(12)
        msg   = os.urandom(secrets.randbelow(1<<9))
        data  = os.urandom(secrets.randbelow(1<<9))
        ciph0, mac0 = ciph_mac = AES_GCM_encrypt(key, nonce, msg, data)
        C = AES.new(key, AES.MODE_GCM, nonce=nonce)
        C.update(data)
        ciph1, mac1 = C.encrypt_and_digest(msg)
        assert mac0 == mac1 and ciph0 == ciph1
        msg1 = AES_GCM_decrypt(key, nonce, ciph_mac, data)
        assert msg1 == msg

if __name__=='__main__':
    import os, secrets
    sanity_check()
