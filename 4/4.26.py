#!/usr/bin/env python3

# this is 2.16 (CBC bitflipping) for CTR, which is trivial
# as in CTR mode the plaintext is xored against the generated
# stream, hence it is directly vulnerable to bitflipping: any bit
# flipped in the ciphertext will be flipped in the decrypted text

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

BS  = 16

## SECRET DATA
PREF = b'comment1=cooking%20MCs;userdata='
SUFF = b';comment2=%20like%20a%20pound%20of%20bacon'
Key = get_random_bytes(BS)
Nonce = get_random_bytes(BS//2)
##

def encrypt(userdata: str) -> bytes:
    userdata = userdata.replace(';','";"').replace('=','"="').encode()
    data = PREF + userdata + SUFF
    return AES.new(Key, AES.MODE_CTR, nonce=Nonce).encrypt(data)

# contrary to 2.16, here we can even decode the decrypted text without any problem!
TARGET = ';admin=true;'
def decrypt(ciph: bytes) -> bool:
    data = AES.new(Key, AES.MODE_CTR, nonce=Nonce).decrypt(ciph).decode()
    print(data)
    return TARGET in data

if __name__=='__main__':
    assert not decrypt(encrypt(TARGET))
    # as in 2.16, we assume we already know BS and the prefix size
    PREF_SIZE = len(PREF)
    target = bytearray(TARGET.encode())
    # we flip the parity bit of the filtered bytes of the target
    flips = [i for i,c in enumerate(target) if c in b';=']
    for b in flips:
        target[b] ^= 1
    target = target.decode()
    ciph = encrypt(target)
    # and simply flip them back in the ciphertext to 
    ciph = bytearray(ciph)
    for b in flips:
        ciph[PREF_SIZE+b] ^= 1
    assert decrypt(ciph)
