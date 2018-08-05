#!/usr/bin/env python3

F = open('8.txt','r')
I = [L.strip() for L in F.readlines()]
F.close()

BS = 16

for L in I:
    cnt = len(set(L[i:i+BS] for i in range(0,len(L),BS)))
    tot = len(L)//BS
    if cnt<tot:
        print("%d/%d distinct blocks" % (cnt,tot))
        print(L)
