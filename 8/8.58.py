#!/usr/bin/env pypy3

import secrets
from arith import small_factors, CRT_combine, invmodp


# Params
p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
q = 335062023296420808191071248367701059461  # order of g
assert pow(g,q,p) == 1

y1 = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
a1,b1 = 0,1<<20

y2 = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733
a2,b2 = 0,1<<40


# https://en.wikipedia.org/wiki/Pollard's_kangaroo_algorithm
def pollard_lambda(y, a,b, k=None, g=g,p=p):
    # solves y = g^x with a ≤ x ≤ b
    # let m = mean of f
    # then T will roughly mark a pt every m indices
    # hence a pt roughly has a proba 1/m to be marked
    # let N be the number of points marked by T
    # W will also roughly jump N times between indices b and xT
    # with a proba ~1/m to be caught each jump
    # hence W roughly has a proba 1-(1-1/m)^N to be caught overall
    # let N = c*m for some cst c
    # then 1-(1-1/m)^(c*m) ~ 1-e^(-c)
    # c = 4 should be good enough

    # pseudo-random index jump
    f = lambda y: 1<<(y%k)

    if k is None:  # finding optimal k
        tmin = float('inf')
        for k in range(10,30):
            m = (1<<k)//k
            N = 4*m
            t = N + (b-a+N*m)//m
            if t<tmin:
                tmin = t; kmin = k
        k = kmin

    m = (1<<k)//k
    N = 4*m
    print(f'k\t{k}\nN\t{N}\nE[iter]\t{tmin}')

    # the tame kangaroo T starts at g^b for N "random" jumps
    xT = 0
    yT = pow(g,b,p)
    for _ in range(N):
        dx = f(yT)
        xT += dx
        yT = (yT*pow(g,dx,p)) % p

    # the wild kangaroo W starts at y and jumps from there
    # until it reaches one of the T pos. (hence ultimately yT)
    #    or its index distance xW exceeds b-a+xT
    #       (we must have a+xW ≤ x+xW ≤ b+xT)
    xW = 0
    yW = y
    while a+xW <= b+xT:
        dx = f(yW)
        xW += dx
        yW = (yW*pow(g,dx,p)) % p
        if yW == yT:
            # g^(x+xW) = g^(b+xT)  mod p
            #    x+xW  =    b+xT   mod q
            return b+xT-xW


if __name__=='__main__':
    ## Examples
    x1 = pollard_lambda(y1, a1,b1)
    print(x1)
    assert pow(g,x1,p) == y1
    print()
    
    x2 = pollard_lambda(y2, a2,b2)
    print(x2)
    assert pow(g,x2,p) == y2
    print()

    ## Practical attack
    # generate Bob's key
    _b = secrets.randbelow(q)  # private < q
    B  = pow(g, _b, p)         # public

    # PH attack
    F = [r for r,m in small_factors((p-1)//q)]
    X = 0; R = 1
    for r in F:
        # we skip to the important part: Eve has deduced _b%r
        x = _b%r
        X,R = CRT_combine(X,R, x,r)

    # we know b = X        mod R
    #         b = X + K*R  mod q

    # Rewrite the problem:
    #   B = g^(X + K*R)
    #   B*g^(-X) = (g^R)^K
    Bp = (B * invmodp(pow(g,X,p),p)) % p
    gp = pow(g,R,p)

    # New DL problem:
    #   B' = g'^K  with K in [0, (q-1)/R]
    K  = pollard_lambda(Bp, 0,(q-1)//R, g=gp)
    b_ = X + K*R
    print(b_)
    assert b_ == _b
