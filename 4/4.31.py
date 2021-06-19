#!/usr/bin/env python4

import os, time


## ===== HMAC ===== ##
import hashlib

def bxor(A,B):
    assert len(A)==len(B)
    return bytes(a^b for a,b in zip(A,B))

# Handmade HMAC - https://en.wikipedia.org/wiki/HMAC
# equivalent to:
#   from Cryptodome.Hash import HMAC, SHA1
#   HMAC.new(K, msg=m, digestmod=SHA1).digest()

def HMAC_SHA1(K: bytes, m: bytes) -> bytes:
    H = lambda x: hashlib.sha1(x).digest()
    BS = 64  # 512 bits = 64 bytes
    if len(K)>BS:
        K = H(K)
    K += bytes(BS-len(K))
    opad = b'\x5c'*BS
    ipad = b'\x36'*BS
    return H(bxor(K,opad) + H(bxor(K,ipad) + m))


## ===== SERVER ===== ##
PORT = 9000

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse as urlparse
from threading import Thread
import json

class TimingLeakWebApp(BaseHTTPRequestHandler):
    _K = os.urandom(16)

    def insecure_compare(self, A,B):
        if len(A)!=len(B):
            return False
        for a,b in zip(A,B):
            if a!=b:
                return False
            time.sleep(0.005)  # 5 ms is enough
        return True

    def do_GET(self):
        url = urlparse.urlparse(self.path)
        params = urlparse.parse_qs(url.query)
        content = {'error': 'invalid request'}
        try:
            fil = params['file'][0].encode()
            sig = params['signature'][0]
            mac = HMAC_SHA1(self._K, fil).hex()
            print(f'server > {mac}')
            accept = self.insecure_compare(sig,mac)
            content = {'accepted': accept}
        except KeyError:
            pass
        content = json.dumps(content).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)


## ===== MALICIOUS CLIENT ===== ##
import requests

def guess_mac(fil='foo'):
    url = f'http://localhost:{PORT}/'
    params = {'file': fil}
    sig = ['0']*40
    for i in range(len(sig)):
        dtmax = 0.
        for c in '0123456789abcdef':
            sig[i] = c
            params['signature'] = ''.join(sig)
            req = requests.get(url, params=params)
            if req.json()['accepted']:
                return ''.join(sig)
            else:
                dt = req.elapsed.total_seconds()
                print(f'{1000.*dt:.2f} ms')
                if dt>dtmax:
                    dtmax = dt
                    cmax = c
        sig[i] = cmax


## ===== MAIN ===== ##
if __name__=='__main__':
    print(f'Serving on port {PORT}...', end=' ')
    httpd = HTTPServer(('', PORT), TimingLeakWebApp)
    httpd_thread = Thread(target=httpd.serve_forever, daemon=True)
    httpd_thread.start()
    print('done.')
    mac = guess_mac('toto')
    print(f'guess  > {mac}')
