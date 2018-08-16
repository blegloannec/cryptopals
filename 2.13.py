#!/usr/bin/env python3

from Crypto.Cipher import AES
import random
random.seed()

def parse_profile(S):
    D = {}
    for E in S.split('&'):
        L,R = E.split('=')
        D[L] = R
    return D

def profile_for(email):
    assert(c not in email for c in '&=')
    prof = ('email=%s&uid=10&role=user'%email).encode()
    return prof

def randbin(S):
    return bytes(random.randint(0,255) for _ in range(S))

def PKCS7(BS,M):
    assert(BS<=256)
    r = len(M)%BS
    if r>0:
        M += bytes([BS-r]*(BS-r))
    return M

def unPKCS7(BS,M):
    assert(len(M)%BS==0)
    if M[-1]<BS and M[-1]<len(M) and all(M[i]==M[-1] for i in range(len(M)-M[-1],len(M)-1)):
        M = M[:-M[-1]]
    return M

BS = 16
Key = randbin(BS)

def encrypt_profile_for(email):
    M = PKCS7(BS,profile_for(email))
    Ciph = AES.new(Key,AES.MODE_ECB)
    C = Ciph.encrypt(M)
    return C

def decrypt_profile(Cprof):
    Ciph = AES.new(Key,AES.MODE_ECB)
    M = unPKCS7(BS,Ciph.decrypt(Cprof))
    return parse_profile(M.decode())

## Attack
# build a first email such that the 3rd plaintext block is padded "user"
user_profile = encrypt_profile_for('x'*(2*BS-len('email=&uid=10&role=')))
print(decrypt_profile(user_profile))
# build a second email such that the 2nd plaintext block is padded "admin"
# (assuming that '\x11' is an accepted character...)
email_admin = 'x'*(BS-len('email=')) + PKCS7(BS,b'admin').decode()
tricky_profile = encrypt_profile_for(email_admin)
print(decrypt_profile(tricky_profile))
admin_block = tricky_profile[BS:2*BS]
# replace the 3rd block of the encrypted user profile by the encrypted admin block
admin_profile = user_profile[:2*BS] + admin_block
# here we go
print(decrypt_profile(admin_profile))
