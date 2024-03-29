#!/usr/bin/env python3

import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

BS = 16


data_file = 'data/19.txt'  # NB: this also works well for 20.txt
# we "cheat" a bit by setting the input to lowercase and extracting the charset
# (but this could mostly be guessed anyway)
with open(data_file, 'rb') as F:
    _DATA = [base64.b64decode(line.strip()).lower()
             for line in F.readlines()]
ALPHA = set(b''.join(_DATA))
zero = bytes(BS//2)
_key = get_random_bytes(BS)
CIPH = [bytearray(AES.new(_key, AES.MODE_CTR, nonce=zero).encrypt(msg))
        for msg in _DATA]


# because the nonce is the same, all the "columns" of the ciphertexts are
# xored with the same byte, allowing frequency attacks (provided we have
# enough texts)
# here we do a more basic & brutal charset attack (not exactly what was
# expected, but, as suggested by the statement, this is not really
# interesting anyway...)
DECIPH = [bytearray(ciph) for ciph in CIPH]
nb_col = max(len(ciph) for ciph in CIPH)
for b in range(nb_col):
    col = [(i, ciph[b]) for i, ciph in enumerate(CIPH) if b < len(ciph)]
    score_max = 0
    for c in ALPHA:
        x = col[0][1]^c
        # trying xor byte b = x
        if all(c^x in ALPHA for _, c in col):
            # this gives an acceptable charset
            # let us maximize the number of [ a-z]
            score = sum(int(c^x == ord(' ') or
                            ord('a') <= c^x <= ord('z'))
                        for _, c in col)
            if score > score_max:
                score_max = score
                x_max = x
    for i, _ in col:
        DECIPH[i][b] ^= x_max


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
