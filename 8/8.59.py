#!/usr/bin/env python3

import eccrypto as ec
from arith import small_factors, CRT_combine


# Curve params
P = 233970423115425145524320034830162017933  # prime
_a = P-95051
_b = 11279326
Gx, Gy = 182, 85518893674295321206118380980485522083
Go = 29246302889428143187362802287225875743  # order of G

ec.set_params(_a, _b, P)
G = ec.Point(Gx,Gy)
assert G.is_valid()
assert (Go*G).is_zero()


# Alternative b params
BO = [(210, 233970423115425145550826547352470124412),
      (504, 233970423115425145544350131142039591210),
      (727, 233970423115425145545378039958152057148)]


if __name__=='__main__':
    # Alice's key
    _sec, Pub = ec.gen_key(G, Go)

    # PH attack
    k = 0; m = 1
    Used = []
    for b,o in BO:
        F = [r for r,m in small_factors(o) if m==1]
        for r in F:
            if r not in Used:
                Used.append(r)

                # find an element of order r
                H = (o//r)*ec.random_point(b=b)
                while H.is_zero():
                    H = (o//r)*ec.random_point(b=b)
                assert not H.is_valid()
                assert (r*H).is_zero()

                # Eve sends H to A and receives _sec*H
                S = _sec*H
                l = 0
                while not S.is_zero():
                    l += 1
                    S -= H

                # sec = l mod r
                k,m = CRT_combine(k,m, l,r)
                if m >= Go: break
        if m >= Go: break

    print(k)
    assert k == _sec
