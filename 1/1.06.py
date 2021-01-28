#!/usr/bin/env python3

import base64, cryptolib

# Hamming test
#A = b'this is a test'
#B = b'wokka wokka!!!'
#print(cryptolib.hamming(A,B))

def analyze_single(I):
    Smax = -1
    for k in range(256):
        O = cryptolib.bxor_repeat(I, bytes([k]))
        S = sum(int(chr(c) in cryptolib.Alphanum) for c in O)
        if S>Smax:
            Smax = S
            Omax = O
            kmax = k
    return kmax,Omax

def analyze(Data, KSmin=2, KSmax=40):
    B = 10
    norm = (lambda KS: sum(cryptolib.hamming(Data[i*KS:(i+1)*KS],Data[(i+1)*KS:(i+2)*KS]) for i in range(B))/(B*KS))
    KS = min(range(KSmin,KSmax+1), key=norm)
    print('Detected key size:', KS)
    OSubs = [analyze_single(Data[i::KS]) for i in range(KS)]
    K = bytes(k for k,_ in OSubs)
    OSubs = [Sub for _,Sub in OSubs]
    O = bytes(OSubs[i%KS][i//KS] for i in range(len(Data)))
    return K,O

def main():
    F = open('data/6.txt','r')
    Data = base64.b64decode(F.read())
    F.close()
    K,O = analyze(Data)
    print('Discovered key:', K.decode())
    print()
    print(O.decode())

main()
