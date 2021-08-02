#!/usr/bin/env python3

def invmodp(n, p):
    # only for prime p
    return pow(n, p-2, p)

def small_factors(n, fmax=1<<16):
    F = []
    for p in range(2, fmax):
        m = 0
        while n%p == 0:
            n //= p
            m += 1
        if m:
            F.append((p,m))
    return F

def bezout(a,b):
    if b==0:
        return (a, 1, 0)
    g,u,v = bezout(b, a%b)
    return (g, v, u-(a//b)*v)

def invmod(a, n):
    g,u,_ = bezout(a,n)
    assert g==1
    return u%n

def CRT_combine(a,p, b,q):
    g,u,v = bezout(p,q)
    assert g==1
    pq = p*q
    return ((b*u*p+a*v*q)%pq, pq)


# === Shanks-Tonelli === #
import random
random.seed()

def legendre(a,p): # p odd prime
    l = pow(a,(p-1)//2,p)
    return -1 if l==p-1 else l

def random_non_residue(p):
    a = random.randint(0,p)
    while legendre(a,p)!=-1:
        a = random.randint(0,p)
    return a

def _shanks_tonelli(a,p):
    # p and odd prime, a a quadratic residue
    # we assume legendre(a,p) == 1
    # returns a solution R, the other one will be -R mod p
    # factor p-1 = s*2^e with s odd
    s,e = p-1,0
    while s%2==0:
        s //= 2
        e += 1
    # if e = 1, ie n = p mod 3, the solutions are +/- n^((p+1)/4)
    if e==1:
        return pow(a,(p+1)//4,p)
    # pick a non-residue (randomly, but could start with 2 and try incrementally)
    n = random_non_residue(p)
    x = pow(a,(s+1)//2,p)
    b = pow(a,s,p)
    g = pow(n,s,p)
    r = e
    while True:
        t,m = b,0
        while t!=1:
            t = (t*t)%p
            m += 1
        if m==0:
            return x
        gs = pow(g,1<<(r-m-1),p)
        g = (gs*gs)%p
        x = (x*gs)%p
        b = (b*g)%p
        r = m

def shanks_tonelli(a,p):
    if p&1 and legendre(a,p)==1:
        return _shanks_tonelli(a,p)
