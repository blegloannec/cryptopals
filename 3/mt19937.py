#!/usr/bin/env python3

# https://en.wikipedia.org/wiki/Mersenne_Twister

class MT19937:
    # Standard 32 bits constants
    w = 32
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    u = 11
    d = 0xFFFFFFFF
    s = 7
    b = 0x9D2C5680
    t = 15
    c = 0xEFC60000
    l = 18
    f = 1812433253
    mask = (1<<w)-1
    lower_mask = (1<<r)-1
    upper_mask = ~lower_mask & mask
    
    def __init__(self, seed=None):
        # Create a length n array to store the state of the generator
        self.MT = [0]*self.n
        self.index = self.n+1
        if seed is not None:
            self.seed(seed)

    # Initialize the generator from a seed
    def seed(self, seed):
        self.index = self.n
        self.MT[0] = seed & self.mask
        for i in range(1, self.n):
            self.MT[i] = (self.f * (self.MT[i-1]^(self.MT[i-1]>>(self.w-2))) + i) & self.mask

    # Extract a tempered value based on MT[index]
    # calling twist() every n numbers
    def extract_number(self):
        if self.index>=self.n:
            assert self.index==self.n, 'Generator was never seeded'
            self.twist()
        y = self.MT[self.index]
        y ^= (y>>self.u) & self.d
        y ^= (y<<self.s) & self.b
        y ^= (y<<self.t) & self.c
        y ^= y>>self.l
        self.index += 1
        return y & self.mask

    def __call__(self):
        return self.extract_number()
    
    # Generate the next n values from the series x_i
    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.upper_mask) | (self.MT[(i+1)%self.n] & self.lower_mask)
            xA = x>>1
            if x&1:
                xA ^= self.a
            self.MT[i] = self.MT[(i+self.m)%self.n] ^ xA
        self.index = 0


if __name__=='__main__':
    rng = MT19937(555)
    for _ in range(1<<20):
        rng()
    assert rng()==3026751584
