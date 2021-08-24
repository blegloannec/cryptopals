#!/usr/bin/env python3

# for arbitrary precision, we use decimals instead of fractions
# as it is much faster
from decimal import Decimal, getcontext
getcontext().prec = 80


def Vec(X):
    return [Decimal(x) for x in X]

def vec_str(u):
    return  '['+'\t'.join(str(x) for x in u)+']'

def _is_zero(u):
    return all(x.is_zero() for x in u)

def _dot(u,v):
    return sum(x*y for x,y in zip(u,v))

def _proj(u,v):
    r = _dot(u,v) / _dot(u,u)
    return [r*x for x in u]


def gram_schmidt(B):
    n = len(B[0])
    Q = []
    for v in B:
        q = v.copy()
        for u in Q:
            p = _proj(u,v)
            for i in range(n):
                q[i] -= p[i]
        Q.append(q)
    return Q


def LLL(B, delta=Decimal(0.99)):
    B = B.copy()
    Q = gram_schmidt(B)

    def mu(i,j):
        v = B[i]
        u = Q[j]
        return _dot(v,u)/_dot(u,u)

    n = len(B)
    k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            mkj = mu(k,j)
            if abs(mkj) > 0.5:
                mkj = round(mkj)
                for i in range(n):
                    B[k][i] -= mkj*B[j][i]
                Q = gram_schmidt(B)
        if _dot(Q[k],Q[k]) >= (delta - mu(k,k-1)**2) * _dot(Q[k-1],Q[k-1]):
            k += 1
        else:
            B[k],B[k-1] = B[k-1],B[k]
            Q = gram_schmidt(B)
            k = max(k-1, 1)
    return B


def _sanity_check():
    B = [Vec([ -2,    0,    2,    0]),
         Vec([1/2,   -1,    0,    0]),
         Vec([ -1,    0,   -2,  1/2]),
         Vec([ -1,    1,    1,    2])]
    B = LLL(B)
    for b in B:
        print(vec_str(b))

if __name__=='__main__':
    _sanity_check()
