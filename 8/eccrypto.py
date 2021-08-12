#!/usr/bin/env python3

from copy import copy
import secrets, hashlib
from arith import invmodp, legendre, shanks_tonelli


## === Weierstrass y² = x³ + ax + b === ##

# Curve params
P = 233970423115425145524320034830162017933
_a = P-95051
_b = 11279326

def set_params(a=None, b=None, p=None):
    global P,_a,_b
    if a is not None: _a = a
    if b is not None: _b = b
    if p is not None: P = p


class Point:
    def __init__(self, x=0, y=0):
        self.x = x%P
        self.y = y%P
        # we should always check that the point is on the curve
        # but we do not do it here to allow some of the attacks
        #assert self.is_valid()

    def is_valid(self):
        return self.is_zero() or \
            (self.y*self.y - pow(self.x,3,P) - _a*self.x - _b)%P==0

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


## === ECDSA === ##

_G  = Point(182, 85518893674295321206118380980485522083)
_Go = 29246302889428143187362802287225875743  # *prime* order of G

def set_base_point(G: Point, order: int):
    global _G,_Go
    _G  = G
    _Go = order

def H(msg: bytes) -> int:
    # BLAKE2b with 256-bit output
    return int.from_bytes(hashlib.blake2b(msg, digest_size=32).digest(), 'big')

def dsa_sign(msg, priv):
    k = 1+secrets.randbelow(_Go-1)
    r = (k*_G).x % _Go
    s = ((H(msg) + priv*r) * invmodp(k,_Go)) % _Go
    return (r, s)

def dsa_verify(msg, sig, Pub):
    r,s = sig
    sinv = invmodp(s,_Go)
    u1 = (H(msg) * sinv) % _Go
    u2 = (r * sinv) % _Go
    R = u1*_G + u2*Pub
    return r == R.x % _Go


## === Montgomery Bv² = u³ + Au² + u === ##

# The idea behind this section is to introduce an isomorphic
# representation of elliptic curves in which the scaling
# operation can be computed more efficiently by a single-coord.
# approach called "ladder".
# The ladder approach identifies (u,±v), as well as (0,0) (actual
# point on the Montgomery curve) and 0 the neutral/identity
# at infinity.

# we use the same P
_A = 534
_B = 1

def set_montgomery_params(A=None, B=None, p=None):
    global P,_A,_B
    if A is not None: _A = A
    if B is not None: _B = B
    if p is not None: P = p

def montgomery_is_valid(u, v=None):
    if v is None:  # single-coordinate check
        v2 = (invmodp(_B,P)*(pow(u,3,P) + _A*u*u + u))%P
        return legendre(v2,P)==1
    # point check
    return (_B*v*v - pow(u,3,P) - _A*u*u - u)%P==0

def montgomery_v_from_u(u):
    # output is None if no solution
    # if output is v, -v is also solution
    Bv2 = (pow(u,3,P) + _A*u*u + u) % P
    v2 = (Bv2 * invmodp(_B,P)) % P
    return shanks_tonelli(v2, P)

def montgomery_ladder(u: int, k: int) -> int:
    # we should check that the coordinate u is on the curve
    # (otherwise it would be on the twist)
    # but we do not do it here to allow some of the attacks
    #assert montgomery_is_valid(u)
    u2,w2 = 1,0
    u3,w3 = u,1
    for i in range(P.bit_length()-1,-1,-1):
        b = 1 & (k >> i)
        if b:
            u2,u3 = u3,u2
            w2,w3 = w3,w2
        u3,w3 = pow(u2*u3-w2*w3,2,P), (u*pow(u2*w3-w2*u3,2,P))%P
        u2,w2 = pow(u2*u2-w2*w2,2,P), (4*u2*w2*(u2*u2+_A*u2*w2+w2*w2))%P
        if b:
            u2,u3 = u3,u2
            w2,w3 = w3,w2
    return (u2*invmodp(w2,P))%P
