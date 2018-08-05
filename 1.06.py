#!/usr/bin/env python3

import base64

def nb_ones(x):
    o = 0
    while x:
        o += x&1
        x >>= 1
    return o

def hamming(A,B):
    assert(len(A)==len(B))
    return sum(nb_ones(a^b) for a,b in zip(A,B))

# Hamming test
#A = b'this is a test'
#B = b'wokka wokka!!!'
#print(hamming(A,B))

Alpha = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '.!\n\r\t")
def analyze_single(I):
    Smax = -1
    for k in range(256):
        O = bytes(k^i for i in I)
        S = sum(int(chr(c) in Alpha) for c in O)
        if S>Smax:
            Smax = S
            Omax = O
            kmax = k
    return kmax,Omax

def analyze(Data, KSmin=2, KSmax=40):
    B = 10
    norm = (lambda KS: sum(hamming(Data[i*KS:(i+1)*KS],Data[(i+1)*KS:(i+2)*KS]) for i in range(B))/(B*KS))
    KS = min(range(KSmin,KSmax+1), key=norm)
    print('Detected key size:',KS)
    OSubs = [analyze_single(Data[i::KS]) for i in range(KS)]
    K = bytes(k for k,_ in OSubs)
    OSubs = [Sub for _,Sub in OSubs]
    O = bytes(OSubs[i%KS][i//KS] for i in range(len(Data)))
    return K,O

def main():
    F = open('6.txt','r')
    Data = base64.b64decode(F.read())
    F.close()
    K,O = analyze(Data)
    print('Discovered key:',K.decode())
    print()
    print(O.decode())

main()
