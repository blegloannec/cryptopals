#!/usr/bin/env python3

class InvalidPadding(Exception):
    pass

def unPKCS7(BS,M):
    if len(M)%BS!=0:
        raise InvalidPadding('Invalid message size')
    if M and M[-1]<BS:
        if any(M[i]!=M[-1] for i in range(len(M)-M[-1],len(M)-1)):
            raise InvalidPadding('Invalid padding content')
        M = M[:-M[-1]]
    return M

BS = 16

for M in [b'ICE ICE BABY\x04\x04\x04\x04',
          b'ICE ICE BABY\x05\x05\x05\x05',
          b'ICE ICE BABY\x01\x02\x03\x04']:
    try:
        print(unPKCS7(BS,M))
    except InvalidPadding as E:
        print(E)
