#!/usr/bin/env python3

from copy import copy
import secrets
from arith import invmodp, shanks_tonelli


# Curve params
P = 3
_a = 0
_b = 1

def set_params(a=None, b=None, p=None):
    global P,_a,_b
    if a is not None: _a = a
    if b is not None: _b = b
    if p is not None: P = p


class Point:
    def __init__(self, x=0, y=0):
        self.x = x%P
        self.y = y%P

    def is_valid(self):
        return (self.y*self.y - pow(self.x,3,P) - _a*self.x - _b)%P==0

    def is_zero(self):
        return isinstance(self, Zero)

    def __neg__(self):
        return Point(self.x, -self.y)

    def __eq__(self, B):
        return self.x==B.x and self.y==B.y

    def __add__(self, B):
        if self.is_zero():
            return copy(B)
        if B.is_zero():
            return copy(self)

        if self.x==B.x:
            if (self.y+B.y)%P==0:  # inverse case
                return Zero()
            else:
                m = ((3*self.x*self.x + _a)*invmodp(2*self.y,P)) % P
        else:
            m = ((B.y-self.y)*invmodp(B.x-self.x,P)) % P
        x = (m*m - self.x - B.x) % P
        y = (m*(self.x - x) - self.y) % P
        return Point(x,y)

    def __sub__(self, B):
        return self+(-B)
    
    def __rmul__(self, k):
        assert isinstance(k,int) and k>=0
        if k==0:
            return Zero()
        res = (k>>1)*(self+self)
        if k&1:
            res += self
        return res

    def __str__(self):
        return f'({self.x}, {self.y})'


class Zero(Point):
    def __str__(self):
        return '0'


def gen_key(G: Point, Gord: int):
    a = secrets.randbelow(Gord)  # private
    A = a*G                      # public
    return (a, A)

def random_point(a=None, b=None):
    if a is None: a = _a
    if b is None: b = _b
    while True:
        x = secrets.randbelow(P)
        y2 = (pow(x,3,P) + a*x + b) % P
        y = shanks_tonelli(y2, P)
        if y is not None:
            return Point(x,y)
