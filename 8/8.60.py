#!/usr/bin/env python3

import eccrypto as ec
import secrets
from arith import small_factors, CRT_combine

# Weierstrass params
P = 233970423115425145524320034830162017933  # prime
_a = P-95051
_b = 11279326
Co = 233970423115425145498902418297807005944  # order of the curve

Gx, Gy = 182, 85518893674295321206118380980485522083
Go = 29246302889428143187362802287225875743  # order of G

ec.set_params(a=_a, b=_b, p=P)
G = ec.Point(Gx, Gy)

# Montgomery params
_A = 534
_B = 1

ec.set_montgomery_params(A=_A, B=_B)

# Isomorphism W ~ M
w2m = lambda W: (W.x-178, W.y)
m2w = lambda u,v: ec.Point(u+178, v)


if __name__=='__main__':
    ## Sanity check
    for _ in range(10):
        k = secrets.randbelow(Go)
        W = k*G
        U,V = w2m(W)
        assert ec.montgomery_is_valid(U,V)
        u,v = w2m(G)
        u = ec.montgomery_ladder(u, k)
        assert u == U
        v = ec.montgomery_v_from_u(u)
        assert v==V or P-v==V

    ## Twist example
    u = 76600469441198017145391791613091732004
    u11 = ec.montgomery_ladder(u, 11)
    print(u11, '?!')
    v = ec.montgomery_v_from_u(u)
    print(u,v)
    print()

    ## Twist order and PH attack
    # NB: ±sec are undistinguishable through ladder() so we won't
    #     we able to exactly identify sec, but both work as private
    #     key so whatever...
    To = 2*P+2 - Co
    print('twist order', To)
    F = [q for q,m in small_factors(To, fmax=1<<24) if m==1]

    sec,_ = ec.gen_key(G, Go)  # Alice's key

    Kand = [0]; Q = 1
    for q_idx, q in enumerate(F):
        # find an element of order q on the twisted curve
        h = 0
        while h==0:
            u = secrets.randbelow(P)
            # u is not on the original curve <=> u is on the/any twist
            if not ec.montgomery_is_valid(u):
                assert ec.montgomery_ladder(u, To)==0
                h = ec.montgomery_ladder(u, To//q)
        assert ec.montgomery_ladder(h, To)==0

        # Eve sends h to Alice and receives ladder(h, sec)
        x = ec.montgomery_ladder(h, sec)

        # the ladder approach identifies (u,±v) (also (0,0) and 0 the neutral)
        # ladder(u, k) == ladder(u,-k)
        # so we always have 2 solutions to our DL problems
        # brute-force for the first solution (SLOW)
        k = next(k for k in range(q) if ec.montgomery_ladder(h, k)==x)
        # -k is also solution

        # then sec = ±k mod q
        # update the 4 new candidates
        Kand = [CRT_combine(s,Q, l,q)[0] for s in Kand for l in (k,q-k)]
        Q *= q
        # Eve now has at most 4 candidates for sec mod Q

        if q_idx>0:
            # to avoid multiplying by 2 the size of K at each step,
            # Eve does an additional query with an element of order Q (composite)
            while True:
                u = secrets.randbelow(P)
                if not ec.montgomery_is_valid(u):
                    h = ec.montgomery_ladder(u, To//Q)
                    # additional check to find an element of order exactly Q
                    # and not a strict divisor of Q
                    if all(ec.montgomery_ladder(h, r)!=0 for r in F[:q_idx+1]):
                        break
            # Eve sends h and receives:
            x = ec.montgomery_ladder(h, sec)
            # Eve filters out the 2 invalid candidates
            Kand = [k for k in Kand if ec.montgomery_ladder(h, k)==x]
            # size Kand is at most 2

        print(q_idx, Kand)

    print(sec%Q)
    assert any(sec%Q==k for k in Kand)

    # then we would conclude using Pollar's lambda attack
    # but we skip that out of scope part here...
