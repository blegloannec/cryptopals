#!/usr/bin/env python3

import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

BS = 16


data_file = 'data/20.txt'
# we cheat a bit by setting the input to lowercase and extracting the charset
_DATA = [base64.b64decode(line.strip()).lower()
         for line in open(data_file, 'rb').readlines()]
ALPHA = set(b''.join(_DATA))
zero = bytes(BS//2)
_key = get_random_bytes(BS)
CIPH = [bytearray(AES.new(_key, AES.MODE_CTR, nonce=zero).encrypt(msg))
        for msg in _DATA]


# because the nonce is the same, all the "columns" of the ciphertexts are
# xored with the same byte
period = min(len(ciph) for ciph in CIPH)
DECIPH = [bytearray(ciph[:period]) for ciph in CIPH]
for b in range(period):
    score_max = 0
    for c in ALPHA:
        x = DECIPH[0][b]^c
        # trying xor byte b = x
        if all(deciph[b]^x in ALPHA for deciph in DECIPH):
            # this gives an acceptable charset
            # let us maximize the number of [ a-z]
            score = sum(int(deciph[b]^x == ord(' ') or
                            ord('a') <= deciph[b]^x <= ord('z'))
                        for deciph in DECIPH)
            if score > score_max:
                score_max = score
                x_max = x
    for deciph in DECIPH:
        deciph[b] ^= x_max


# check
for deciph, msg in zip(DECIPH, _DATA):
    msg = msg.decode()
    deciph = deciph.decode()
    ham = sum(int(a!=b) for a,b in zip(deciph, msg))
    if ham == 0:
        print(' ', deciph)
    else:
        print('|', deciph, '|', ham, 'error(s)')
        print('|', msg, '|')
