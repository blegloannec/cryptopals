#!/usr/bin/env python3

def PKCS7(BS,M):
    assert(BS<=256)
    r = len(M)%BS
    if r>0:
        M += bytes([BS-r]*(BS-r))
    return M

M = b'YELLOW SUBMARINE'
print(PKCS7(20,M))
