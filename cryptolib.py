import itertools, random
from Crypto.Cipher import AES
random.seed()

Alphanum = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '.!\n\r\t")

def bxor(A,B):
    assert(len(A)==len(B))
    return bytes(a^b for a,b in zip(A,B))

def bxor_repeat(A,B):
    if len(A)<len(B):
        A,B = B,A
    return bytes(a^b for a,b in zip(A,itertools.cycle(B)))

def nb_ones(x):
    o = 0
    while x:
        o += x&1
        x >>= 1
    return o

def hamming(A,B):
    assert(len(A)==len(B))
    return sum(nb_ones(a^b) for a,b in zip(A,B))

def AES_ECB_encrypt(Key, M):
    C = AES.new(Key,AES.MODE_ECB)
    return C.encrypt(M)

def AES_ECB_decrypt(Key, M):
    C = AES.new(Key,AES.MODE_ECB)
    return C.decrypt(M)

def AES_CBC_encrypt(Key, IV, M):
    C = AES.new(Key,AES.MODE_CBC,IV)
    return C.encrypt(M)

def AES_CBC_decrypt(Key, IV, M):
    C = AES.new(Key,AES.MODE_CBC,IV)
    return C.decrypt(M)

def PKCS7_pad(M, BS=16):
    assert 0<BS<256
    r = len(M)%BS
    M += bytes([BS-r]*(BS-r))
    return M

class InvalidPadding(Exception):
    pass

def PKCS7_unpad(M, BS=16):
    if M:
        if len(M)%BS!=0:
            raise InvalidPadding('Invalid message size')
        if not 0<M[-1]<=BS:
            raise InvalidPadding('Invalid padding size')
        if any(M[i]!=M[-1] for i in range(len(M)-M[-1],len(M)-1)):
            raise InvalidPadding('Invalid padding content')
        M = M[:-M[-1]]
    return M

def randbin(S=16):
    return bytes(random.randint(0,255) for _ in range(S))
