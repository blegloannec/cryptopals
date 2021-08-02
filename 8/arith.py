#!/usr/bin/env python3

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

def bezout(a, b):
    if b==0:
        return (a, 1, 0)
    g,u,v = bezout(b, a%b)
    return (g, v, u-(a//b)*v)

def CRT_combine(a,p, b,q):
    _,u,v = bezout(p,q)
    pq = p*q
    return ((b*u*p+a*v*q)%pq, pq)
