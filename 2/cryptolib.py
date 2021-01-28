import itertools, os, secrets
from Cryptodome.Cipher import AES

Alphanum = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '.!\n\r\t")


# handmade bytes xor
# same as Crypto.Util.strxor.strxor
def bxor(A,B):
    assert len(A)==len(B)
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
    assert len(A)==len(B)
    return sum(nb_ones(a^b) for a,b in zip(A,B))


# AES helper functions
def AES_ECB_encrypt(Key, M):
    C = AES.new(Key, AES.MODE_ECB)
    return C.encrypt(M)

def AES_ECB_decrypt(Key, M):
    C = AES.new(Key, AES.MODE_ECB)
    return C.decrypt(M)

def AES_CBC_encrypt(Key, IV, M):
    C = AES.new(Key, AES.MODE_CBC, IV)
    return C.encrypt(M)

def AES_CBC_decrypt(Key, IV, M):
    C = AES.new(Key, AES.MODE_CBC, IV)
    return C.decrypt(M)


# handmade padding
# same as Crypto.Util.Padding.pad(M, BS, style='pkcs7')
def PKCS7_pad(M, BS=16):
    assert 0<BS<256
    r = len(M)%BS
    M += bytes([BS-r]*(BS-r))
    return M

# same as Crypto.Util.Padding.unpad(M, BS, style='pkcs7')
def PKCS7_unpad(M, BS=16):
    if M:
        if len(M)%BS!=0:
            raise ValueError('Invalid message size')
        if not 0<M[-1]<=BS:
            raise ValueError('Invalid padding size')
        if any(M[i]!=M[-1] for i in range(len(M)-M[-1],len(M)-1)):
            raise ValueError('Invalid padding content')
        M = M[:-M[-1]]
    return M


# random bytes
# same as Crypto.Random.get_random_bytes(S)
def randbin(S=16):
    return os.urandom(S)

def randint(a, b):
    assert a<=b
    return a + secrets.randbelow(b-a+1)
