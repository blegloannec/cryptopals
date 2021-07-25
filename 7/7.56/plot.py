#!/usr/bin/env python3

import sys
import matplotlib.pyplot as plt

if __name__=='__main__':
    L = sys.stdin.readlines()
    W = len(L)
    X = list(range(256))
    for i in range(len(L)):
        Y = list(map(float, L[i].split()))
        assert len(Y) == len(X)
        ax = plt.subplot(W, 1, i+1)
        ax.set_xlim(0, 255)
        ax.set_ylim(1./256.-15e-5, 1./256.+15e-5)
        plt.plot(X, Y)
    plt.tight_layout()
    plt.show()
