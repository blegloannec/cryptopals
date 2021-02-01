#!/usr/bin/env python3

from threading import Thread
from queue import SimpleQueue
import dhlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes

BS = 16


class Alice(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
        self.p = dhlib._p
        self.g = dhlib._g
        self.Ka, self.KA = dhlib.gen_key(self.p, self.g)
    
    def run(self):
        assert self.outbox is not None
        self.outbox.put((self.p, self.g, self.KA))
        KB = self.inbox.get()
        s = pow(KB, self.Ka, self.p)
        sdata = s.to_bytes((s.bit_length()+7)//8, 'big')
        key = SHA1.new(sdata).digest()[:BS]
        iv = get_random_bytes(BS)
        msg = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
        ciph = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg, BS))
        self.outbox.put((ciph, iv))
        ciph, iv = self.inbox.get()
        msgB = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciph), BS)
        assert msg == msgB
        print('Alice: msg ok, done')


class Bob(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
    
    def run(self):
        assert self.outbox is not None
        p, g, KA = self.inbox.get()
        Kb, KB = dhlib.gen_key(p, g)
        self.outbox.put(KB)
        s = pow(KA, Kb, p)
        sdata = s.to_bytes((s.bit_length()+7)//8, 'big')
        key = SHA1.new(sdata).digest()[:BS]
        ciph, iv = self.inbox.get()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciph), BS)
        print('Bob:  ', msg)
        iv = get_random_bytes(BS)
        ciph = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg, BS))
        self.outbox.put((ciph, iv))
        print('Bob:   done')


def std_scenario():
    A = Alice()
    B = Bob(A.inbox)
    A.outbox = B.inbox
    A.start(); B.start()
    A.join(); B.join()


class Eve(Thread):
    def __init__(self, outA=None, outB=None):
        Thread.__init__(self)
        self.inA = SimpleQueue()
        self.inB = SimpleQueue()
        self.outA = outA
        self.outB = outB
    
    def run(self):
        assert self.outA is not None
        assert self.outB is not None
        p, g, KA = self.inA.get()
        self.outB.put((p, g, p))  # KA := p (= 0)
        KB = self.inB.get()
        self.outA.put(p)          # KB := p (= 0)
        ciph, iv = self.inA.get()
        self.outB.put((ciph, iv))
        key = SHA1.new(b'').digest()[:BS]  # s = 0
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciph), BS)
        print('Eve:  ', msg)
        ciph, iv = self.inB.get()
        self.outA.put((ciph, iv))
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciph), BS)
        print('Eve:  ', msg)
        print('Eve:   done')


def mitm_scenario():
    A = Alice()
    B = Bob()
    M = Eve(A.inbox, B.inbox)
    A.outbox = M.inA; B.outbox = M.inB
    A.start(); B.start(); M.start()
    A.join(); B.join(); M.join()


if __name__=='__main__':
    std_scenario()
    print()
    mitm_scenario()
