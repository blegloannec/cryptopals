#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Util.strxor import strxor
import random


BS = 16
IV = bytes(BS)

def CBC_MAC(P, K, IV=IV):
    return AES.new(K, AES.MODE_CBC, iv=IV).encrypt(pad(P, BS))[-BS:]


CODE = b"alert('MZA who was that?');\n"
KEY  = b'YELLOW SUBMARINE'

rand_char_block = lambda: bytes(random.randint(32,126) for _ in range(BS))
is_char_block   = lambda B: all(32<=b<127 for b in B)

if __name__=='__main__':
    print(CODE)
    mac = CBC_MAC(CODE, KEY)
    print(mac.hex())

    # Arbitrary data solution
    # 4 blocks padded msg:
    # | code₁ | code₂ | mid_block | (pad_block) |
    code        = b"alert('Ayo, the Wu is back!');//"  # length 2*BS
    mid_iv      = AES.new(KEY, AES.MODE_CBC, iv=IV).encrypt(code)[-BS:]
    pad_block   = b'\x10'*BS
    dmac        = AES.new(KEY, AES.MODE_ECB).decrypt(mac)
    mid_target  = strxor(pad_block, dmac)
    dmid_target = AES.new(KEY, AES.MODE_ECB).decrypt(mid_target)
    mid_block   = strxor(mid_iv, dmid_target)
    payload     = code + mid_block
    print(payload)
    mac1 = CBC_MAC(payload, KEY)
    print(mac1.hex())
    assert mac == mac1

    # Printable chars solution
    # proba: (95/256)^16 ~ 0.37
    # expected #tries: ~7.7e6
    # 5 blocks padded msg:
    # | code₁ | code₂ | add_block | mid_block | (pad_block) |
    random.seed(42)  # finds a solution quickly enough
    while not is_char_block(mid_block):
        add_block = rand_char_block()
        mid_iv1   = AES.new(KEY, AES.MODE_CBC, iv=mid_iv).encrypt(add_block)
        mid_block = strxor(mid_iv1, dmid_target)
    payload = code + add_block + mid_block
    print(payload.decode())
    mac1 = CBC_MAC(payload, KEY)
    print(mac1.hex())
    assert mac == mac1
