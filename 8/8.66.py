#!/usr/bin/env python3

from copy import copy
import eccrypto as ec
import secrets


## SECRET DATA
_d = secrets.randbelow(1<<64)
dsize = _d.bit_length()  # assumed known for convenience


## Faulty implementation
class Fault(Exception):
    pass

class FaultyPoint(ec.Point):
    def __init__(self, B: ec.Point):
        super().__init__(B.x, B.y)

    def fault(self, B):
        # deterministic "random" fault
        return (self.x*B.x) % 10000 == 0  # for a p = 1/10000 proba. here

    def __add__(self, B):
        if self.fault(B):
            raise Fault
        return FaultyPoint(super().__add__(B))  # /!\ convert to this class!

    __radd__ = __add__

    def __rmul__(self, k):
        # we redefine the scalar mult. to fit the statement
        # of the challenge, but the attack would work as well
        # with our implementation or any other
        assert k>0  # for this challenge, but doesn't matter...
        R = copy(self)
        for i in range(k.bit_length()-2, -1, -1):
            R += R
            if (k>>i)&1:
                R += self
        return R

def random_faulty_point():
    return FaultyPoint(ec.random_point())

def oracle(Q: ec.Point) -> bool:
    try:
        _d*Q
    except Fault:
        # proba 1-(1-1/p)^#op
        # where #op = nb of add operations
        #           = dsize + #1s in _d
        return False
    return True


def main():
    # Sanity check
    print('Sanity check...', end=' ', flush=True)
    for _ in range(30):
        k = secrets.randbelow(1<<128)
        Q1 = ec.random_point()
        Q2 = FaultyPoint(Q1)
        try:
            R = k*Q2
        except Fault:
            continue
        assert k*Q1 == R
    print('ok.')

    # Attack
    print(bin(_d))
    d = 1
    for _ in range(dsize-2):
        d <<= 1
        while True:
            Q = random_faulty_point()
            try:
                dQ = d*Q
            except Fault:
                # fault in the common path
                continue
            f0 = f1 = True
            try: # next op in case of 0
                dQ+dQ
            except Fault:
                # fault for sure in the 0-branch
                f0 = False
            try: # next 2 ops in case of 1
                R = dQ+Q
                R+R
            except Fault:
                # fault for sure in the 1-branch
                f1 = False
            # fi = False => fault for sure in the i-branch
            # fi = True  => we do not know, there is no immediate fault
            #               but there might be one further along the path
            if f0!=f1 and oracle(Q):
                # no fault => we found the new bit for sure
                if f1:
                    d |= 1
                break
        print(bin(d), end='\r')

    # last bit special case: this time there are not following ops,
    # the ops are exactly the same + one last add if bit is 1
    d <<= 1
    while True:
        Q = random_faulty_point()
        try:
            dQ = d*Q
        except Fault:
            continue
        try:  # last op if bit is 1
            dQ+Q
        except Fault:
            if not oracle(Q):
                d |= 1
            break
    print(bin(d))
    assert d == _d

if __name__=='__main__':
    main()
