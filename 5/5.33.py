#!/usr/bin/env python3

import secrets, hashlib

# Diffie-Hellman takes place in (Z/pZ)* with p a large prime
# g is a generator of this group

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

def gen_key(p,g):
    a = secrets.randbelow(p)  # private
    A = pow(g,a,p)            # public
    return (a,A)

a,A = gen_key(p,g)
b,B = gen_key(p,g)

# Alice sends A to Bob
# Bob   sends B to Alice

# common secret
sa = pow(B,a,p)  # g^(ab)
sb = pow(A,b,p)  # idem
assert sa==sb

# deriving a 128-bit key
siz = p.bit_length()
h = hashlib.sha256(sa.to_bytes(siz,'big')).digest()
key,mac_key = h[:16],h[16:]
print(key.hex())
