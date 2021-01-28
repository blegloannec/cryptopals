#!/usr/bin/env python3

import cryptolib

def parse_profile(S):
    D = {}
    for E in S.split('&'):
        L,R = E.split('=')
        D[L] = R
    return D

def profile_for(email):
    assert all(c not in email for c in '&=')
    prof = f'email={email}&uid=10&role=user'.encode()
    return prof

BS = 16
Key = cryptolib.randbin(BS)

def encrypt_profile_for(email):
    M = cryptolib.PKCS7_pad(profile_for(email),BS)
    C = cryptolib.AES_ECB_encrypt(Key,M)
    return C

def decrypt_profile(Cprof):
    M = cryptolib.AES_ECB_decrypt(Key,Cprof)
    M = cryptolib.PKCS7_unpad(M,16)
    return parse_profile(M.decode())

## Attack
# build a first email such that the 3rd plaintext block is padded "user"
user_profile = encrypt_profile_for('x'*(2*BS-len('email=&uid=10&role=')))
print(decrypt_profile(user_profile))
# build a second email such that the 2nd plaintext block is padded "admin"
# (assuming that '\x11' is an accepted character...)
email_admin = 'x'*(BS-len('email=')) + cryptolib.PKCS7_pad(b'admin',BS).decode()
tricky_profile = encrypt_profile_for(email_admin)
print(decrypt_profile(tricky_profile))
admin_block = tricky_profile[BS:2*BS]
# replace the 3rd block of the encrypted user profile by the encrypted admin block
admin_profile = user_profile[:2*BS] + admin_block
# here we go
print(decrypt_profile(admin_profile))
