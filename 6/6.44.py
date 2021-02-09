#!/usr/bin/env python3

from Cryptodome.Hash import SHA1
from dsalib import p, q, g


# public key
y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

# parsing data
In = open('data/44.txt', 'r').readlines()
Data = []
for i in range(0, len(In), 4):
    msg = In[i].strip('\n').split(': ')[1]
    s = int(In[i+1].strip().split(': ')[1])
    r = int(In[i+2].strip().split(': ')[1])
    h = In[i+3].strip().split(': ')[1]
    assert h == SHA1.new((msg).encode()).hexdigest().lstrip('0')
    h = int(h, 16) % q
    Data.append((s, r, h))


# assume that two messages have the same k
# s1 = (h1+xr)/k          mod q
# s2 = (h2+xr)/k          mod q
# then s1-s2 = (h1-h2)/k  mod q
# k = (h1-h2)/(s1-s2)     mod q
for i in range(len(Data)):
    s1, r1, h1 = Data[i]
    for j in range(i+1, len(Data)):
        s2, r2, h2 = Data[j]
        try:
            # assume same k for msg i & j
            k = ((h1-h2) * pow(s1-s2, -1, q)) % q
            # then try retrieving x from k (see 6.43)
            x0 = ((s1*k - h1) * pow(r1, -1, q)) % q
            if pow(g, x0, p) == y:
                print(f'{i:2d} {j:2d} {hex(x0)}')
                x = x0
        except ValueError:
            pass
res = SHA1.new(hex(x)[2:].encode()).hexdigest()
print(res)
assert res == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
