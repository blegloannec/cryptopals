#!/usr/bin/env python3

from Cryptodome.Hash import SHA1
from dsalib import p, q, g


## DSA implementation ##
# see dsalib.py
# run it directly for a sanity check


## Attack ##
# message
msg = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
#assert SHA1.new(msg).hexdigest() == 'd2d0714f014a9784047eaeccf956520045c45265'

# public key
y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

# signature
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940

# attack
h = int.from_bytes(SHA1.new(msg).digest(), 'big')
r_inv = pow(r, -1, q)
# crack the private key by brute-forcing on k
for k in range(1<<16):
    # s = (h+xr)/k mod q
    # x = (sk-h)/r mod q
    x = ((s*k - h) * r_inv) % q
    if pow(g, x, p) == y:
        break
res = SHA1.new(hex(x)[2:].encode()).hexdigest()
print(res)
assert res == '0954edd5e0afe5542a4adf012611a91912a3ec16'
