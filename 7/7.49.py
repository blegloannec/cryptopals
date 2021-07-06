#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
from copy import copy
import re

BS = 16


def CBC_MAC(P, K, IV=bytes(BS)):
    return AES.new(K, AES.MODE_CBC, iv=IV).encrypt(pad(P.encode(), BS))[-BS:]


class Request:
    def __init__(self, client, to_id, amount):
        self.M = f'from={client.id}&to={to_id}&amount={amount}'
        self.IV = get_random_bytes(BS)
        self.MAC = CBC_MAC(self.M, client.key, self.IV)

class Request2:
    def __init__(self, client, to_list):
        L = ';'.join(f'{to_id}:{amount}' for to_id,amount in to_list)
        self.M = f'from={client.id}&tx_list={L}'
        self.MAC = CBC_MAC(self.M, client.key)


class Client:
    def __init__(self, name):
        self.name = name
        self.key = get_random_bytes(BS)
        self.id = None

    def request(self, to_id, amount):
        return Request(self, to_id, amount)

    def request2(self, to_list):
        return Request2(self, to_list)


class Server:
    def __init__(self):
        self.Clients = []

    def register(self, client):
        client.id = len(self.Clients)
        self.Clients.append(client)

    def check_request(self, req):
        try:
            from_id,to_id,amount = re.fullmatch(r'from=(\d+)&to=(\d+)&amount=(\d+)', req.M).groups()
            from_id = int(from_id)
            from_client = self.Clients[from_id]
            to_id = int(to_id)
            to_client = self.Clients[to_id]
            assert req.MAC == CBC_MAC(req.M, from_client.key, req.IV)
            print(f'Accepted: {from_client.name} -> {amount} -> {to_client.name}')
            return True
        except:
            print(f'Rejected: {req.M}')
        return False

    def check_request2(self, req):
        #try:
        from_id,tx_list = re.fullmatch(r'from=(\d+)&tx_list=(.+)', req.M).groups()
        to_list = [tuple(map(int, ta.split(':'))) for ta in tx_list.split(';')]
        from_id = int(from_id)
        from_client = self.Clients[from_id]
        assert req.MAC == CBC_MAC(req.M, from_client.key)
        to_list_str = ', '.join(f'{amount} -> {self.Clients[to_id].name}' for to_id,amount in to_list)
        print(f'Accepted from {from_client.name}: {to_list_str}')
        return True
        #except:
        #    print(f'Rejected: {req.M}')
        #return False


if __name__=='__main__':
    alice = Client('alice')
    bob = Client('bob')
    charlie = Client('charlie')
    eve = Client('eve')
    bank = Server()
    bank.register(alice)
    bank.register(bob)
    bank.register(charlie)
    bank.register(eve)

    # client-controlled IV scenario
    req = alice.request(bob.id, 1000000)
    assert bank.check_request(req)
    forged_req = copy(req)
    forged_req.M = forged_req.M.replace(f'to={bob.id}', f'to={eve.id}')
    forged_req.IV = bytes(a^b^c for a,b,c in zip(req.M.encode(), forged_req.M.encode(), req.IV))
    assert bank.check_request(forged_req)

    print()
    # constant IV scenario
    req = alice.request2([(bob.id, 1000), (charlie.id, 2000)])
    assert bank.check_request2(req)
    m = pad(req.M.encode(), BS).decode() + f'{}:1000000'
    p = pad(m.encode())[-BS:]
    # ?!...
