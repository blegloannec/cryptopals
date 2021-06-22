#!/usr/bin/env pypy3

import mt19937
import os, base64, secrets
import time
import itertools


def rng_stream(seed):
    rng = mt19937.MT19937(seed)
    while True:
        yield from rng().to_bytes(4, 'big')

def mtcrypt(key: int, mess: bytes) -> bytes:
    return bytes(c^k for c,k in zip(mess, rng_stream(key)))


timestamp = lambda: int(time.time())

def pwd_token(nbytes=16, seed=None) -> str:
    if seed is None:
        seed = timestamp()
    return bytes(itertools.islice(rng_stream(seed), nbytes)).hex()

def was_mt_gen(tok: str, dt=3600):
    t = timestamp()
    for seed in range(t, t-dt, -1):
        if tok == pwd_token(len(tok)//2, seed):
            return seed
    return None


if __name__=='__main__':
    ## sanity check
    print('Sanity check...', end=' ')
    for _ in range(20):
        mess = os.urandom(2000)
        key  = secrets.randbits(32)
        ciph = mtcrypt(key, mess)
        assert ciph != mess
        mess1 = mtcrypt(key, ciph)
        assert mess1 == mess
    print('ok.\n')

    ## known plaintext attack
    print('Known plaintext attack...')
    plain = b'A'*14
    _mess = base64.b85encode(os.urandom(secrets.randbelow(50))) + plain
    _key  = secrets.randbits(16)
    print('!', _key)
    ciph = mtcrypt(_key, _mess)
    for k in range(1<<16):  # brute-force on the key
        if mtcrypt(k, ciph).endswith(plain):
            print('?', k)
    print('done.\n')

    ## password token oracle
    cases = 5
    for i in range(1, cases+1):
        print(f'Password token oracle ({i}/{cases})...', end=' ')
        mt_gen = bool(secrets.randbits(1))
        tok = pwd_token() if mt_gen else secrets.token_hex(16)
        delay = 1+secrets.randbelow(5)
        print(f'wait {delay}s...', end=' ')
        time.sleep(delay)
        assert (was_mt_gen(tok) is not None) == mt_gen
        print('ok.')
