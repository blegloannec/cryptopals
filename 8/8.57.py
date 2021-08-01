#!/usr/bin/env python3

import secrets, hmac

##  === Helpers === ##
randint = lambda a,b: a+secrets.randbelow(b-a+1)
int_to_bytes = lambda n: n.to_bytes((n.bit_length()+7)//8, 'big')


## === DH & crypto === ##
p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771  # prime
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143

def gen_key(p=p, g=g):
    a = secrets.randbelow(p)  # private
    A = pow(g, a, p)          # public
    return (a, A)

# order of g:
q = 236234353446506858198510045061214171961
assert pow(g,q,p) == 1
# private keys can be considered mod q

def MAC(k: int, m: bytes) -> bytes:
    return hmac.new(int_to_bytes(k), msg=m, digestmod='blake2b').digest()


## === Arithmetic === ##
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
        return (a,1,0)
    g,u,v = bezout(b,a%b)
    return (g,v,u-(a//b)*v)

def rev_crt(a,p, b,q):
    _,u,v = bezout(p,q)
    pq = p*q
    return ((b*u*p+a*v*q)%pq, pq)


## === MAIN == ##
if __name__=='__main__':
    # Diffie-Hellman
    a,A = gen_key()
    b,B = gen_key()
    # Since we explicitly know the order q of g,
    # we can (and have to) reduce the exponents mod q.
    # /!\ This is crucial as in the attack h^b ≠ h^(b%q)
    #     (since h will not be a power of g)
    #     and we obviously cannot have enough small factors
    #     to guess the (anyway useless) "full" b.
    a %= q
    b %= q
    assert pow(B,a,p) == pow(A,b,p)


    # Pohlig-Hellman attack on the Discrete Log
    # 1. Get enough small prime divisors r of p-1
    F = [r for r,m in small_factors((p-1)//q) if m==1]

    X = 0  # result
    R = 1  # CRT mod

    # and for each of them
    for r in F:
        # find an element of order r (assuming it is a
        # simple prime factor, i.e. multiplicity 1)
        h = pow(randint(1,p-1), (p-1)//r, p)
        while h==1:
            h = pow(randint(1,p-1), (p-1)//r, p)

        # 2-3. Eve sends h to Bob as if it was A
        sB = pow(h,b,p)
        msg = b'crazy flamboyant for the rap enjoyment'
        mac = MAC(sB, msg)

        # 4. Bob sends (msg, mac) to Eve
        # Brute-force search for x such that h^x = sB mod p
        # (small-enough Discrete Log problem)
        # NB: Because we only have access to sB through the mac
        #     we cannot use smarter approaches such as BSGS...
        x = 0
        y = 1
        while MAC(y, msg) != mac:
            y = (h*y)%p
            x += 1

        # 5. We have b = x mod r, use CRT to guess b
        X,R = rev_crt(X,R, x,r)
        if R >= q:
            break

    print(X)
    assert X == b
