#!/usr/bin/env python3

from mt19937 import MT19937 as MT
import os

def get_bit(x,i):
    return (x>>i)&1 if 0<=i<32 else 0


## === temper === ##
_opr = lambda y,a,b: y ^ ((y>>a) & b)
_opl = lambda y,a,b: y ^ ((y<<a) & b)

# more convenient rewriting of the operation
def opr(y,a,b):
    z = 0
    for i in range(32):
        if get_bit(b,i):
            z |= (get_bit(y,i)^get_bit(y,i+a))<<i
        else:
            z |= get_bit(y,i)<<i
    return z

opl  = lambda y,a,b: opr(y,-a,b)

def temper(y):
    y = opr(y, MT.u, MT.d)
    y = opl(y, MT.s, MT.b)
    y = opl(y, MT.t, MT.c)
    y = opr(y, MT.l, MT.mask)
    return y


## == untemper == ##
def inv_opr(y,a,b):
    z = 0
    for i in range(31, -1, -1):
        if get_bit(b,i):
            z |= (get_bit(y,i)^get_bit(z,i+a))<<i
        else:
            z |= get_bit(y,i)<<i
    return z

def inv_opl(y,a,b):
    z = 0
    for i in range(32):
        if get_bit(b,i):
            z |= (get_bit(y,i)^get_bit(z,i-a))<<i
        else:
            z |= get_bit(y,i)<<i
    return z

def untemper(y):
    y = inv_opr(y, MT.l, MT.mask)
    y = inv_opl(y, MT.t, MT.c)
    y = inv_opl(y, MT.s, MT.b)
    y = inv_opr(y, MT.u, MT.d)
    return y


## == MAIN == ##
if __name__=='__main__':
    _seed = int.from_bytes(os.urandom(4), 'big')
    rng = MT(_seed)
    # NB: We start with a fresh RNG, so right after the first twist.
    #     Otherwise we would have to try each window of n consecutive values
    #     within 2n consecutive outputs (until we get the predictions right).
    State = [untemper(rng()) for _ in range(MT.n)]
    rng_clone = MT()
    rng_clone.MT = State
    rng_clone.index = MT.n
    for _ in range(1<<15):
        assert rng() == rng_clone()

# Q: How would you modify MT19937 to make this attack hard?
# > Let F : int32 -> int32 be an alternative tempering function.
#   If F is bijective, as it is here, then, because 2^32 is not that huge,
#   it is always possible to fully precompute F^(-1) and lead this attack.
#   If F is not bijective, then it leaves uncertainty when "inversing", which
#   can make the attack impractical, but it breaks the statistical balance
#   of the output, which is terrible for a RNG...
#   One simple idea could be to drop a part of the bits of the output, but,
#   keeping track of the known bits twist after twist, we can theoretically
#   recover the whole state (it would take more than one twist, but
#   truncating the output also implies to twist more often to generate the
#   same quantity of data).
# Q: What would happen if you subjected each tempered output to a
#    cryptographic hash?
# > Hashing each 32-bit tempered output is not good enough (see prev. answer).
#   However, hashing large enough sequences of consecutive outputs seems
#   reasonable. That said, it is not as algorithmically efficient anymore
#   (which is one of the reasons of the popularity of MT).
#   This is by the way the recommended approach in the official MT FAQ:
#   http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/efaq.html
#   "To make it secure, you need to use some Secure Hashing Algorithm with MT.
#    For example, you may gather every eight words of outputs, and compress
#    them into one word (...)"
