#!/usr/bin/env python3

import mt19937
import time, secrets

# we use ms instead of s to go faster

def randsleep():
    time.sleep((40.+secrets.randbelow(1000))/1000.)

def timestamp():
    return int(1000.*time.time())

def toy_routine():
    randsleep()
    seed = timestamp()
    print('!', seed)
    rng = mt19937.MT19937(seed)
    randsleep()
    return rng()

if __name__=='__main__':
    t0 = timestamp()
    x = toy_routine()
    t1 = timestamp()
    for t in range(t0, t1):
        rng = mt19937.MT19937(t)
        if rng()==x:
            print('?', t)
