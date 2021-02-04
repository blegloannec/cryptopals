#!/usr/bin/env python3

import cryptolib

## SECRET DATA
PREF = b'comment1=cooking%20MCs;userdata='
SUFF = b';comment2=%20like%20a%20pound%20of%20bacon'
BS  = 16
IV  = cryptolib.randbin(BS)
Key = cryptolib.randbin(BS)
##

def encrypt(userdata: str) -> bytes:
    # NB1: The statement is unclear about "quoting out" ';' and '=' from the whole
    #      data or only from the userdata part. We consider here that it makes more
    #      sense to only apply this to the userdata. This does not change anything
    #      to the attack anyway...
    # NB2: We encode the data here. Otherwise, it would simply be possible to
    #      inject arbitrary data and to build an arbitrary CBC encrypted message
    #      block-by-block past the prefix (no need for the bitflipping attack).
    userdata = userdata.replace(';','";"').replace('=','"="').encode()
    data = PREF + userdata + SUFF
    return cryptolib.AES_CBC_encrypt(Key, IV, cryptolib.pad(data, BS))

TARGET = b';admin=true;'
def decrypt(ciph: bytes) -> bool:
    data = cryptolib.unpad(cryptolib.AES_CBC_decrypt(Key, IV, ciph), BS)
    # NB: The attack would not work if we had decoded the data here (as the
    #     modified encrypted block will be decrypted to seemingly random data).
    print(data)
    return TARGET in data

if __name__=='__main__':
    assert not decrypt(encrypt(TARGET.decode()))
    # We have seen in previous challenges how to detect:
    #  - ECB/CBC mode
    #  - the block size BS
    #  - the size of the prefix and suffix data
    # hence, to focus on the attack, we assume here that
    # we already know it is CBC, BS and the prefix size.
    PREF_SIZE = len(PREF)
    target = bytearray(TARGET)
    # we flip the parity bit of the filtered bytes of the target
    flips = [i for i,c in enumerate(target) if c in b';=']
    for b in flips:
        target[b] ^= 1
    target = target.decode()
    # we inject the userdata
    r = (-PREF_SIZE)%BS
    ciph = encrypt('0'*r + target)
    # and flip the corresponding bits in the previous block
    off = ((PREF_SIZE-1)//BS)*BS
    ciph = bytearray(ciph)
    for b in flips:
        ciph[off+b] ^= 1
    # this block will be decrypted to seemingly random data
    # the the next one will be corrected to the target
    assert decrypt(ciph)
