#!/usr/bin/env python3

import eccrypto as ec
import secrets
from arith import invmodp, invmod, CRT_combine


## === ECC & ECDSA === ##
P = 233970423115425145524320034830162017933  # prime
_a = P-95051
_b = 11279326
Co = 233970423115425145498902418297807005944  # order of the curve

Gx, Gy = 182, 85518893674295321206118380980485522083
Go = 29246302889428143187362802287225875743  # order of G

ec.set_params(a=_a, b=_b, p=P)
G = ec.Point(Gx, Gy)
ec.set_base_point(G, Go)


def main_DSA():
    a,A = ec.gen_key(G, Go)  # Alice's key
    msg = b'Everybody knows that the boat is leaking'

    sig = ec.dsa_sign(msg, a)
    assert ec.dsa_verify(msg, sig, A)

    # assume Eve can pick the base point she wants (as if it was
    # part of her public key), then it is trivial to forge a perfectly
    # valid key that verifies the signature
    r,s = sig
    # compute the constants
    sinv = invmodp(s,Go)
    u1 = (ec.H(msg) * sinv) % Go
    u2 = (r * sinv) % Go
    R = u1*G + u2*A
    # forge a key
    e = secrets.randbelow(Go)
    Gforged = invmodp(u1 + u2*e, Go)*R
    E = e*Gforged
    # verify
    print('Verifying with forged ECDSA key...', end=' ', flush=True)
    ec.set_base_point(Gforged, Go)
    assert (Go*Gforged).is_zero()
    assert ec.dsa_verify(msg, sig, E)
    print('ok.\n')

if __name__=='__main__':
    main_DSA()


## === RSA === ##
from Cryptodome.Util.number import isPrime, getPrime
import random
random.seed()

def sieve(N=1<<14):
    Primes = []
    Pr = [True]*N
    for p in range(3, N, 2):
        if Pr[p]:
            Primes.append(p)
            for k in range(p*p, N, p):
                Pr[k] = False
    return Primes

def gen_smooth_prime(Primes, s,h, size=1<<8):
    # Randomized strategy, good enough here but surely can be improved.
    # The provided primes list is crucial: the bigger the primes, the
    # faster the iterations but the lower proba. each has to succeed.
    cnt = 1
    while True:
        random.shuffle(Primes)
        print(f'\rGenerating a smooth prime of size {size}... {cnt}', end=' ', flush=True)
        phi_p = 2; Phi_p = [2]
        for r in Primes:
            phi_p *= r
            Phi_p.append(r)
            p = phi_p+1
            if all(pow(s,phi_p//f,p)>1 and pow(h,phi_p//f,p)>1 for f in Phi_p):
                # s and h are primitive roots mod p
                if p.bit_length()>=size and isPrime(p):
                    print('ok.')
                    return (p,Phi_p)
                if p.bit_length()>size<<1:
                    break
            else:
                phi_p //= r
                Phi_p.pop()
        cnt += 1

def DL_solve(s,h, p,Phi):
    ef = 0; emod = 1
    for r in Phi:
        m = (p-1)//r
        # s^e = h mod pf  =>  s^(e*m) = h^m mod pf
        # solve u^e = h^m mod pf  with u = s^m of order r small
        # we could use BSGS or Pollard's rho, but brute-force is good enough here...
        u  = pow(s, m, p)
        ho = pow(h, m, p)
        k = 0; uk = 1
        while uk!=ho:
            k += 1
            uk = (uk*u) % p
        ef,emod = CRT_combine(ef,emod, k,r)
    return (ef,emod)


def main_RSA():
    # /!\ ec.H returns a 256-bit hash, n & nf have to be at least that large.

    ## Alice's key
    p = getPrime(1<<8)
    q = getPrime(1<<8)
    e = 65537                  # public
    d = invmod(e,(p-1)*(q-1))  # private
    n = p*q                    # modulus
    msg = b'Everybody knows the captain lied'
    h = ec.H(msg)
    sig = pow(h,d,n)        # sign
    assert pow(sig,e,n)==h  # verify

    ## Attack
    # we want to find e such s^e = h mod nf, for some nf = pf*qf
    # i.e. s^e = h mod pf and s^e = h mod qf
    print('Sieving...', end=' ', flush=True)
    Primes = sieve(1<<14)
    print('ok.')
    pf,Pf = gen_smooth_prime(Primes, sig,h, 1<<8)
    Primes = [r for r in Primes if r not in Pf]  # filter out primes from pf-1
    qf,Qf = gen_smooth_prime(Primes, sig,h, 1<<8)

    nf = pf*qf

    # /!\ pf-1 and qf-1 are not coprime: they have a factor 2 in common.
    # The congruential system will have a solution iff they are
    # compatible on that factor, i.e. e_pf = e_qf mod 2
    # where e_pf is such that
    # sig^((pf-1)//2 * e_pf) = h^((pf-1)//2) mod pf
    # with sig and h primitive roots mod pf.
    # But if e_pf = 0 mod 2, then h^((pf-1)//2) = 1 mod pf,
    # contradicting the fact that h is a primitive root.
    # Hence the only possibility is
    # e_pf = 1 mod 2 and similarly e_qf = 1 mod 2
    # They are always compatible and there exists a unique solution
    # e mod (pf-1)*(qf-1)//2

    print('DL solving...', end=' ', flush=True)
    epf,emodp = DL_solve(sig,h, pf,Pf)
    eqf,emodq = DL_solve(sig,h, qf,Qf[1:])  # skip 2
    ef,emod = CRT_combine(epf,emodp, eqf,emodq)
    assert emodp==pf-1 and emodq==(qf-1)//2 and emod==(pf-1)*(qf-1)//2
    print('ok.')

    # Forged key: (ef,df,nf)
    df = invmod(ef, (pf-1)*(qf-1))  # private key (unused here)
    print('Verifying with forged RSA key...', end=' ', flush=True)
    assert pow(sig,ef,nf)==h  # verify
    print('ok.')

def main_RSA_bis():
    # Replacing:
    #  * sig by a random ciphertext ciph
    #  * h by a chosen target plaintext target
    #  * ef by df
    # we can similarly forge a key to decrypt ciph into target.
    ciph = secrets.randbelow(1<<10)
    target = b'Everybody knows that the plague is coming'
    t = int.from_bytes(target, 'big')

    print('Sieving...', end=' ', flush=True)
    Primes = sieve(1<<14)
    print('ok.')
    pf,Pf = gen_smooth_prime(Primes, ciph,t, 1<<8)
    Primes = [r for r in Primes if r not in Pf]
    qf,Qf = gen_smooth_prime(Primes, ciph,t, 1<<8)

    nf = pf*qf

    print('DL solving...', end=' ', flush=True)
    dpf,dmodp = DL_solve(ciph,t, pf,Pf)
    dqf,dmodq = DL_solve(ciph,t, qf,Qf[1:])
    df,_ = CRT_combine(dpf,dmodp, dqf,dmodq)
    print('ok.')

    ef = invmod(df, (pf-1)*(qf-1))  # public key (unused here)
    m = pow(ciph, df, nf)
    msg = m.to_bytes((m.bit_length()+7)//8, 'big')
    print('Decrypting with forged RSA key:', msg)

if __name__=='__main__':
    main_RSA()
    print()
    main_RSA_bis()
