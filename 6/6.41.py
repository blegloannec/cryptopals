#!/usr/bin/env python3

import rsalib, base64, time
from rsalib import int_to_bytes
from Cryptodome.Random import get_random_bytes
from Cryptodome.Random.random import randint


class Server:
    def __init__(self):
        self.k, self.K = rsalib.gen_key(1<<10)
        self.Seen = {}
    
    def decrypt(self, c):
        assert c not in self.Seen
        self.Seen[c] = time.time()
        return rsalib.decrypt(self.k, c)


if __name__=='__main__':
    S = Server()
    e, n = K = S.K
    mess0 = b'platypus:'+base64.b64encode(get_random_bytes(12))
    m0 = int.from_bytes(mess0, 'big')
    print(mess0, hex(m0))
    c0 = rsalib.encrypt(K, m0)  # intercepted
    print('Server:', hex(S.decrypt(c0)))
    s = randint(2, n-1)
    c1 = (pow(s, e, n) * c0) % n
    # c1 = s^e * c0 = (s*m)^e
    # c1^d = s*m
    m1 = S.decrypt(c1)
    m2 = (m1 * pow(s, -1, n)) % n
    mess2 = int_to_bytes(m2)
    print(mess2, hex(m2))
    assert mess2 == mess0
