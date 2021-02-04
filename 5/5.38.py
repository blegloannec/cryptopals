#!/usr/bin/env python3

from threading import Thread
from queue import SimpleQueue
import dhlib
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Random import get_random_bytes
import Cryptodome.Random.random as random

int_to_bytes = lambda n: n.to_bytes((n.bit_length()+7)//8, 'big')

BS = 16
_N, _G = dhlib._p, 2

IDS = [(b'raven@cryptopals.com', b's3cr3t_f34th3rs'),
       (b'hedgehog@cryptopals.com', b's3cr3t_sp1n3s'),
       (b'lizard@cryptopals.com', b's3cr3t_sc4l3s'),
       (b'toucan@cryptopals.com', b'cannot_be_found')]


class SimplifiedSRPClient(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
        self.N = _N
        self.g = _G
        self.Ka, self.KA = dhlib.gen_key(self.N, self.g)  # client DH key
        self.mel, self.pwd = random.choice(IDS)
        print(f'Client: {self.mel.decode()}:{self.pwd.decode()}')
    
    def run(self):
        assert self.outbox is not None
        self.outbox.put((self.mel, self.KA))
        salt, KB, u = self.inbox.get()
        # using the salt, retrieve the server db entry key
        Kx = int.from_bytes(SHA256.new(salt+self.pwd).digest(), 'big')
        sec = pow(KB, self.Ka+u*Kx, self.N)
        # sec = KB^(Ka+u*Kx) = g^(Kb*(Ka+u*Kx))
        key = SHA256.new(int_to_bytes(sec)).digest()
        print('Client: key', key.hex())
        mac = HMAC.new(key, salt, SHA256).digest()
        self.outbox.put(mac)
        ok = self.inbox.get()
        assert ok == b'OK'
        print('Client: ok, done')


class SimplifiedSRPServer(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
        self.N = _N
        self.g = _G
        self.Kb, self.KB = dhlib.gen_key(self.N, self.g)  # server DH key
        # precomp. server db
        self.DB = {}
        for mel, pwd in IDS:
            salt = get_random_bytes(BS)
            Kx = int.from_bytes(SHA256.new(salt+pwd).digest(), 'big')
            KX = pow(self.g, Kx, self.N)
            self.DB[mel] = (salt, KX)  # salt & pwd DH "public" key
    
    def run(self):
        assert self.outbox is not None
        # get client id and retrieve its entry
        mel, KA = self.inbox.get()   
        assert mel in self.DB
        salt, KX = self.DB[mel]
        # in this simplified version, we do not use k to mix KB and KX,
        # we directly use the server "public" key KB instead
        u = int.from_bytes(get_random_bytes(128), 'big')
        self.outbox.put((salt, self.KB, u))
        sec = pow(KA*pow(KX, u, self.N), self.Kb, self.N)
        # sec = g^((Ka+Kx*u)*Kb)
        key = SHA256.new(int_to_bytes(sec)).digest()
        print('Server: key', key.hex())
        mac = self.inbox.get()
        HMAC.new(key, salt, SHA256).verify(mac)
        print('Server: ok')
        self.outbox.put(b'OK')
        print('Server: done')


def std_scenario():
    S = SimplifiedSRPServer()
    C = SimplifiedSRPClient(S.inbox)
    S.outbox = C.inbox
    S.start(); C.start()
    C.join(); S.join()


class MaliciousSimplifiedSRPServer(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
        self.N = _N
        self.g = _G
        self.salt = b'whatever' # anything works
        self.KB = self.g
        self.u = 1
        # server passwords list
        self.pwd_list = []
        for _, pwd in IDS[:-1]:  # exclude the last one
            Kx = int.from_bytes(SHA256.new(self.salt+pwd).digest(), 'big')
            KX = pow(self.g, Kx, self.N)
            self.pwd_list.append((pwd, KX))
    
    def run(self):
        assert self.outbox is not None
        mel, KA = self.inbox.get()
        self.outbox.put((self.salt, self.KB, self.u))
        # the client computes:
        #   sec = pow(KB, self.Ka+u*Kx, self.N)
        #   sec = KB^(Ka+u*Kx)
        #   sec = g^Ka*g^Kx = KA*KX
        # and we know KA
        mac = self.inbox.get()
        self.outbox.put(b'OK')
        print('Server: close connection')
        self.crack_pwd(KA, mac)
    
    def crack_pwd(self, KA, mac):
        for pwd, KX in self.pwd_list:
            sec = (KA*KX) % self.N
            key = SHA256.new(int_to_bytes(sec)).digest()
            try:
                HMAC.new(key, self.salt, SHA256).verify(mac)
                print('Server: password found', pwd)
                return pwd
            except ValueError:
                pass
        print('Server: password NOT found')
        return None


def mitm_scenario():
    # we do not bother implementing the client-side role
    # of the MITM malicious server as it is trivial
    S = MaliciousSimplifiedSRPServer()
    C = SimplifiedSRPClient(S.inbox)
    S.outbox = C.inbox
    S.start(); C.start()
    C.join(); S.join()


if __name__=='__main__':
    std_scenario()
    print()
    mitm_scenario()
