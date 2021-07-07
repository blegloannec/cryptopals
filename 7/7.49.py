#!/usr/bin/env python3

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.strxor import strxor
from copy import copy
from urllib.parse import quote

BS = 16

# the key authenticates the web app. to the bank, not the actual client
_KEY = get_random_bytes(BS)

def CBC_MAC(P: bytes, K: bytes, IV=bytes(BS)):
    return AES.new(K, AES.MODE_CBC, iv=IV).encrypt(pad(P, BS))[-BS:]


class Request:
    def __init__(self, from_id, to_id, amount):
        self.M = f'from={quote(from_id)}&to={quote(to_id)}&amount={quote(str(amount))}'.encode()
        self.IV = get_random_bytes(BS)
        self.MAC = CBC_MAC(self.M, _KEY, self.IV)

class Request2:
    def __init__(self, from_id, to_list):
        L = ';'.join(f'{quote(to_id)}:{quote(str(amount))}' for to_id,amount in to_list)
        self.M = f'from={quote(from_id)}&tx_list={L}'.encode()
        self.MAC = CBC_MAC(self.M, _KEY)


class Client:
    def __init__(self, cid):
        self.id = cid

    def request(self, to_id, amount):
        return Request(self.id, to_id, amount)

    def request2(self, to_list):
        return Request2(self.id, to_list)


def server_check_request(req):
    if hasattr(req, 'IV'):
        valid = req.MAC==CBC_MAC(req.M, _KEY, req.IV)
    else:
        valid = req.MAC==CBC_MAC(req.M, _KEY)
    print(('Accepted:' if valid else 'Rejected:'), req.M)
    return valid


if __name__=='__main__':
    alice = Client('A')
    bob = Client('B')
    charlie = Client('C')
    eve = Client('E')

    ## Client-controlled IV scenario
    # intercept Alice's request and redirect it towards Eve's account
    req = alice.request(bob.id, 1000000)
    assert server_check_request(req)
    forged_req = copy(req)
    forged_req.M = forged_req.M.replace(f'to={bob.id}'.encode(), f'to={eve.id}'.encode())
    forged_req.IV = strxor(strxor(req.M[:BS], forged_req.M[:BS]), req.IV)
    assert server_check_request(forged_req)
    # alternatively, we emit our own request and redirect it from Alice's account
    req = eve.request(eve.id, 1000000)
    assert server_check_request(req)
    forged_req = copy(req)
    forged_req.M = forged_req.M.replace(f'from={eve.id}'.encode(), f'from={alice.id}'.encode())
    forged_req.IV = strxor(strxor(req.M[:BS], forged_req.M[:BS]), req.IV)
    assert server_check_request(forged_req)

    ## Constant IV scenario
    print()
    req = alice.request2([(bob.id, 1000), (charlie.id, 2000)])
    assert server_check_request(req)
    my_req = eve.request2([(eve.id, 1000000)]*2)
    assert server_check_request(my_req)
    # we can glue Alice's request to the tail of our own by inserting a block
    # that will be equal to our first block (xored with the constant IV, 0 here)
    # after being xored with Alice's MAC (as if it was the IV)
    my_req.M = pad(req.M, BS) + strxor(req.MAC, my_req.M[:BS]) + my_req.M[BS:]
    assert server_check_request(my_req)
