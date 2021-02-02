#!/usr/bin/env python3

from threading import Thread
from queue import SimpleQueue
import dhlib
from dhlib import int_to_bytes
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Random import get_random_bytes

BS = 16
_N, _G = dhlib._p, 2
_K = 3


class SRPClient(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
        self.N = _N
        self.g = _G
        self.Ka, self.KA = dhlib.gen_key(self.N, self.g)  # client DH key
        self.k = _K
        self.mel = b'I_am_the_client@cryptopals.com'
        self.pwd = b's3cr3t_p4ssw0rd'
    
    def run(self):
        assert self.outbox is not None
        self.outbox.put((self.mel, self.KA))
        salt, B = self.inbox.get()
        u = int.from_bytes(SHA256.new(int_to_bytes(self.KA)+int_to_bytes(B)).digest(), 'big')
        # using the salt, retrieve the server db entry key
        Kx = int.from_bytes(SHA256.new(salt+self.pwd).digest(), 'big')
        KX = pow(self.g, Kx, self.N)
        sec = pow(B-self.k*KX, self.Ka+u*Kx, self.N)
        # sec = (B-k*KX)^(Ka+u*Kx) = KB^(Ka+u*Kx) = g^(Kb*(Ka+u*Kx))
        key = SHA256.new(int_to_bytes(sec)).digest()
        print('Client: key', key.hex())
        mac = HMAC.new(key, salt, SHA256).digest()
        self.outbox.put(mac)
        ok = self.inbox.get()
        assert ok == b'OK'
        print('Client: ok, done')


class SRPServer(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
        self.N = _N
        self.g = _G
        self.Kb, self.KB = dhlib.gen_key(self.N, self.g)  # server DH key
        self.k = _K
        # precomp. server db
        self.DB = {}
        mel = b'I_am_the_client@cryptopals.com'
        pwd = b's3cr3t_p4ssw0rd'
        salt = get_random_bytes(BS)
        Kx = int.from_bytes(SHA256.new(salt+pwd).digest(), 'big')
        KX = pow(self.g, Kx, self.N)
        self.DB[mel] = (salt, Kx, KX)  # salt & db entry DH key
    
    def run(self):
        assert self.outbox is not None
        # get client id and retrieve its entry
        mel, KA = self.inbox.get()   
        assert mel in self.DB
        salt, Kx, KX = self.DB[mel]
        # B = k*KX + KB
        # linear mix of the entry pub. key with the server pub. key
        B = (self.k*KX + self.KB) % self.N
        self.outbox.put((salt, B))
        u = int.from_bytes(SHA256.new(int_to_bytes(KA)+int_to_bytes(B)).digest(), 'big')
        sec = pow(KA*pow(KX, u, self.N), self.Kb, self.N)
        # sec = g^((Ka+Kx*u)*Kb)
        key = SHA256.new(int_to_bytes(sec)).digest()
        print('Server: key', key.hex())
        mac = self.inbox.get()
        HMAC.new(key, salt, SHA256).verify(mac)
        print('Server: ok')
        self.outbox.put(b'OK')
        print('Server: done')


def scenario():
    S = SRPServer()
    C = SRPClient(S.inbox)
    S.outbox = C.inbox
    S.start(); C.start()
    C.join(); S.join()


if __name__=='__main__':
    scenario()
