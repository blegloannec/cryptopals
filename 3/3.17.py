#!/usr/bin/env python3

import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.strxor import strxor
from Cryptodome.Random import get_random_bytes
import Cryptodome.Random.random as random

BS = 16

## SECRET DATA
_DATA = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
         b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
         b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
         b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
         b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
         b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
         b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
         b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
         b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
         b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']
_KEY = get_random_bytes(BS)
##

def intercept():
    msg = base64.b64decode(random.choice(_DATA))
    iv = get_random_bytes(BS)
    ciph = AES.new(_KEY, AES.MODE_CBC, iv=iv).encrypt(pad(msg, BS))
    return (iv, ciph)

def oracle(iv: bytes, ciph: bytes) -> bool:
    try:
        msg = unpad(AES.new(_KEY, AES.MODE_CBC, iv=iv).decrypt(ciph), BS)
        return True
    except ValueError:
        return False

# CBC padding oracle attack
def guess_block(block: bytes) -> bytes:
    deblock = bytearray([0]*BS)  # AES decrypted block
    for i in range(BS-1, -1, -1):
        # guess deblock[i] knowing deblock[i+1:]
        pad_siz = BS-i
        # choosing the iv, we will force block[i+1:]
        # to be decrypted as the following pad -1 byte
        padding = bytes([pad_siz]*(pad_siz-1))
        iv_suff = strxor(deblock[i+1:], padding)
        # block[i] will have to be decrypted as pad_size
        # for the padding to be valid
        # except for the last byte which will require
        # a second request to confirm the pad '1'
        for b in range(256):
            # try iv[i] = b
            iv = bytes(i) + bytes([b]) + iv_suff
            if oracle(iv, block):
                if i == BS-1: # last byte
                    # check that it is not a false positive:
                    # make sure that the valid pad is '1' and
                    # not '22', '333', '4444', ...
                    # by changing the previous byte in the IV
                    iv = bytes(i-1) + bytes([1, b])
                    if oracle(iv, block):
                        # confirmed
                        break
                else:
                    # block[i] was decrypted to pad_size
                    break
        deblock[i] = b^pad_siz
    return bytes(deblock)

if __name__=='__main__':
    iv, ciph = intercept()
    deciph = b''.join(guess_block(ciph[block_pos:block_pos+BS])
                      for block_pos in range(0, len(ciph), BS))
    pmsg = strxor((iv+ciph)[:-BS], deciph)  # apply CBC xors
    print(pmsg)
    msg = unpad(pmsg, BS)
    print(msg.decode())
