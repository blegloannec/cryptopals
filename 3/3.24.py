#!/usr/bin/env pypy3

import mt19937
import os, secrets
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


def sanity_check(it=20):
    print('Sanity check...', end=' ', flush=True)
    for _ in range(it):
        mess = os.urandom(2000)
        key  = secrets.randbits(32)
        ciph = mtcrypt(key, mess)
        assert ciph != mess
        mess1 = mtcrypt(key, ciph)
        assert mess1 == mess
    print('ok.')

def known_plaintext_attack():
    print('Known plaintext attack...')
    plain = b'A'*14
    _mess = secrets.token_urlsafe(secrets.randbelow(50)).encode() + plain
    _key  = secrets.randbits(16)
    print('!', _key)
    ciph = mtcrypt(_key, _mess)
    for k in range(1<<16):  # brute-force on the key
        if mtcrypt(k, ciph).endswith(plain):
            print('?', k)
    print('done.')

def password_token_oracle(cases=5):
    for i in range(1, cases+1):
        print(f'Password token oracle ({i}/{cases})...', end=' ', flush=True)
        mt_gen = bool(secrets.randbits(1))
        tok = pwd_token() if mt_gen else secrets.token_hex(16)
        delay = 1+secrets.randbelow(5)
        print(f'wait {delay}s...', end=' ', flush=True)
        time.sleep(delay)
        assert (was_mt_gen(tok) is not None) == mt_gen
        print('ok.')


if __name__=='__main__':
    sanity_check()
    print()
    known_plaintext_attack()
    print()
    password_token_oracle()
