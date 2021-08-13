#!/usr/bin/env python3

from copy import copy
from fractions import Fraction


# Vector of Fraction scalar
class Vec:
    def __init__(self, X):
        self.X = [Fraction(x) for x in X]

    def __len__(self):
        return len(self.X)

    def __getitem__(self, i):
        assert 0 <= i < len(self.X)
        return self.X[i]

    def __add__(self, V):
        assert len(self.X) == len(V.X)
        return Vec([x+y for x,y in zip(self.X,V.X)])

    def __neg__(self):
        return Vec([-x for x in self.X])

    def __sub__(self, V):
        assert len(self.X) == len(V.X)
        return Vec([x-y for x,y in zip(self.X,V.X)])

    def __rmul__(self, k):
        assert isinstance(k, Fraction)
        return Vec([k*x for x in self.X])

    def __matmul__(self, V):  # dot product
        assert len(self.X) == len(V.X)
        return sum(x*y for x,y in zip(self.X,V.X))

    def is_zero(self):
        return all(x==Fraction(0) for x in self.X)

    def proj(self, V):
        if self.is_zero():
            return copy(self)
        return ((V@self) / (self@self)) * self

    def __str__(self):
        return '['+'\t'.join(f'{x.numerator}/{x.denominator}' if x.denominator!=1 else str(x.numerator) for x in self.X)+']'


def gram_schmidt(B):
    n = len(B[0])
    Z = Vec([0]*n)
    Q = []
    for i,v in enumerate(B):
        Q.append(v - sum((u.proj(v) for u in Q[:i]), start=Z))
    return Q

def LLL(B, delta):
    B = copy(B)
    Q = gram_schmidt(B)

    def mu(i,j):
        v = B[i]
        u = Q[j]
        return Fraction(v@u,u@u)

    n = len(B)
    k = 1
    while k < n:
        for j in range(k-1,-1,-1):
            if abs(mu(k,j)) > Fraction(1,2):
                B[k] = B[k] - Fraction(round(mu(k,j)))*B[j]
                Q = gram_schmidt(B)
        if Q[k]@Q[k] >= (delta - mu(k,k-1)**2) * (Q[k-1]@Q[k-1]):
            k += 1
        else:
            B[k],B[k-1] = B[k-1],B[k]
            Q = gram_schmidt(B)
            k = max(k-1, 1)
    return B


def main():
    B = [Vec([ -2,    0,    2,    0]),
         Vec([Fraction(1,2),   -1,    0,    0]),
         Vec([ -1,    0,   -2,  Fraction(1,2)]),
         Vec([ -1,    1,    1,    2])]
    B = LLL(B, Fraction(99,100))
    for b in B:
        print(b)

if __name__=='__main__':
    main()
