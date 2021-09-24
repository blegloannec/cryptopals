#!/usr/bin/env python3

import mt19937  # implem. in mt19937.py

# https://www.cplusplus.com/reference/random/mt19937/
# Values can be controlled by the following C++ code:
'''
#include <iostream>
#include <random>
using namespace std;

int main() {
  int seed = 54321;
  mt19937 mt(seed);
  for (int i=0; i<1000; ++i) cout << mt() << endl;
}
'''

if __name__=='__main__':
    seed = 54321
    rng = mt19937.MT19937(seed)
    print('MT19937 check...', end=' ', flush=True)
    for _ in range(10**5):
        rng()
    assert rng()==1827882266
    print('ok')
