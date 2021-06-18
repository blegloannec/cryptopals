#!/usr/bin/env python3

import sha1

def MAC(key: bytes, mess: bytes) -> bytes:
    return sha1.sha1(key + mess)

if __name__=='__main__':
    key  = b'earth'
    mess = b'Ground_Control_to_Major_Tom'
    print(MAC(key, mess).hex())
    print(MAC(key, b'Ground_Control_to_Motor_Jam').hex())
    print(MAC(b'moon', mess).hex())
