#!/usr/bin/env python3

from threading import Thread
from queue import SimpleQueue
import dhlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Hash import SHA1
from Cryptodome.Random import get_random_bytes
from Cryptodome.Random.random import randint

BS = 16


class Alice(Thread):
    def __init__(self, outbox=None):
        Thread.__init__(self)
        self.inbox = SimpleQueue()
        self.outbox = outbox
        self.p, self.g = dhlib._groups[randint(0,2)]
        self.Ka, self.KA = dhlib.gen_key(self.p, self.g)
    
    def run(self):
        assert self.outbox is not None
        self.outbox.put((self.p, self.g))
        assert self.inbox.get() == 'ACK'
        self.outbox.put(self.KA)
        KB = self.inbox.get()
        s = pow(KB, self.Ka, self.p)
        sdata = s.to_bytes((s.bit_length()+7)//8, 'big')
        key = SHA1.new(sdata).digest()[:BS]
        print('Alice: key', key.hex())
        iv = get_random_bytes(BS)
        msg = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor.'
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
        p, g = self.inbox.get()
        self.outbox.put('ACK')
        Kb, KB = dhlib.gen_key(p, g)
        KA = self.inbox.get()
        self.outbox.put(KB)
        s = pow(KA, Kb, p)
        sdata = s.to_bytes((s.bit_length()+7)//8, 'big')
        key = SHA1.new(sdata).digest()[:BS]
        print('Bob:   key', key.hex())
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


# The statement is not clear about the constraints for
# the attack, we will consider the following:
#  - Even though Bob's g will be distinct from Alice's,
#    Eve tries to make them generate the same secret;
#  - Eve tries to only modify g and KA sent to Bob, making
#    the attacks possible in a "half"-MITM situation:
#      A --> E --> B
#      A <-------- B
# Of course, there are simpler attacks without these
# additional constraints.
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
        self.p, g = self.inA.get()
        # picking an attack at random
        attack = randint(0, 2)
        (self.attack1, self.attack2, self.attack3)[attack]()
        print('Eve:   key', self.key.hex())
        ciph, iv = self.inA.get()
        try:
            msg = unpad(AES.new(self.key, AES.MODE_CBC, iv).decrypt(ciph), BS)
        except ValueError:
            # see comments in attack3() code below
            assert attack == 2
            print('Eve:   probabilistic attack FAILED, switching to ACTIVE attack')
            self.attack3_active(ciph, iv)
            return
        print('Eve:  ', msg)
        self.outB.put((ciph, iv))
        ciph, iv = self.inB.get()
        self.outA.put((ciph, iv))
        msg = unpad(AES.new(self.key, AES.MODE_CBC, iv).decrypt(ciph), BS)
        print('Eve:  ', msg)
        print('Eve:   done')
    
    def attack1(self):
        print('Eve:   attack 1, g = 1')
        self.outB.put((self.p, 1))  # g_B := 1
        ack = self.inB.get()
        assert ack == 'ACK'
        self.outA.put(ack)
        KA = self.inA.get()
        self.outB.put(1)       # KA_B := 1
        KB = self.inB.get()
        assert KB == 1
        self.outA.put(KB)
        self.key = SHA1.new(bytes([1])).digest()[:BS]  # s = 1
    
    def attack2(self):
        print('Eve:   attack 2, g = p')
        self.outB.put((self.p, self.p))  # g_B := p (= 0)
        ack = self.inB.get()
        assert ack == 'ACK'
        self.outA.put(ack)
        KA = self.inA.get()
        self.outB.put(0)       # KA_B := 0
        KB = self.inB.get()
        assert KB == 0
        self.outA.put(KB)
        self.key = SHA1.new(b'').digest()[:BS]  # s = 0
    
    def attack3(self):
        print('Eve:   attack 3, g = p-1')
        # In this case, KB = ±1 depending on the parity of Kb.
        # If Kb is even, then KB = 1, s_A = 1 and we can
        # arbitrarily inject KA_B = ±1.
        # If Kb is odd, KB = -1, s_A = ±1 depending on the
        # parity of Ka, and we should inject KA_B = s_A.
        
        # Prop.: If g is a generator of Zₚ*,
        #        Ka is even <=> KA (= g^Ka) is a square mod p
        #   => trivial
        #   <= KA = x², ∃n / x = gⁿ, KA = g²ⁿ = g^Ka,
        #      hence Ka = 2n mod p-1, with p-1 even,
        #      hence Ka is even
        # In that case, we can use Euler's criterion to test
        # whether KA is a square (and then choose KA_B = ±1).
        # https://en.wikipedia.org/wiki/Euler%27s_criterion

        # Problem: In practice, the given g = 2, probably for
        # optimized computation purposes, and is NOT a primitive
        # root. Even worse, its order might be odd, in which case
        # two Ka of different parity might generate the same KA
        # but different secrets when given KB = -1.
        # Solution: We pick KA_B at random, there is a 1/4 chance
        # to fail (Kb odd & bad choice), in which case we detect
        # if by a padding error and switch to a fully active
        # attack (as A and B do not share the same key).
        self.outB.put((self.p, self.p-1))  # g_B := p-1 (= -1)
        ack = self.inB.get()
        assert ack == 'ACK'
        self.outA.put(ack)
        KA = self.inA.get()
        # primitive root deterministic case:
        #even_Ka = pow(KA, (p-1)//2, p)==1
        # randomized case:
        even_Ka = randint(0,1)==0
        self.outB.put(1 if even_Ka else self.p-1)
        KB = self.inB.get()
        assert KB==1 or KB==self.p-1
        self.outA.put(KB)
        self.s = 1 if KB==1 or even_Ka else self.p-1
        sdata = self.s.to_bytes((self.s.bit_length()+7)//8, 'big')
        self.key = SHA1.new(sdata).digest()[:BS]
    
    def attack3_active(self, ciphA, ivA):
        sA = self.p - self.s
        sdataA = sA.to_bytes((sA.bit_length()+7)//8, 'big')
        keyA = SHA1.new(sdataA).digest()[:BS]
        print("Eve:   Alice's key", keyA.hex())
        msg = unpad(AES.new(keyA, AES.MODE_CBC, ivA).decrypt(ciphA), BS)
        print('Eve:  ', msg)
        ciph = AES.new(self.key, AES.MODE_CBC, ivA).encrypt(pad(msg, BS))
        self.outB.put((ciph, ivA))
        ciph, iv = self.inB.get()
        msg = unpad(AES.new(self.key, AES.MODE_CBC, iv).decrypt(ciph), BS)
        print('Eve:  ', msg)
        ciphA = AES.new(keyA, AES.MODE_CBC, iv).encrypt(pad(msg, BS))
        self.outA.put((ciphA, iv))
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
