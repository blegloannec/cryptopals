#!/usr/bin/env python3

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

class TimingLeakWebApp(BaseHTTPRequestHandler):
    _K = os.urandom(16)

    def insecure_compare(self, A,B):
        if len(A)!=len(B):
            return False
        for a,b in zip(A,B):
            if a!=b:
                return False
            time.sleep(0.0025)  # /!\ this time 2.5 ms is NOT enough
        return True

    def do_GET(self):
        url = urlparse.urlparse(self.path)
        params = urlparse.parse_qs(url.query)
        try:
            fil = params['file'][0].encode()
            sig = params['signature'][0]
            mac = HMAC_SHA1(self._K, fil).hex()
            print(f'server > {mac}')
            if self.insecure_compare(sig,mac):
                content = b'ok'
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(500, 'Bad signature')
        except:
            self.send_error(400)


## ===== MALICIOUS CLIENT ===== ##
import requests

def guess_mac(fil='foo'):
    url = f'http://localhost:{PORT}/'
    params = {'file': fil}
    # guessing k digits at a time multiplies the delay by k
    # the complexity is ~ S/k * B^k
    #                 for B the base and
    #                     S the size of the hash in base B
    # below we consider 2 digits at a time to double the delay
    # which is good enough here
    sig = ['0']*40
    for i in range(0, len(sig), 2):
        dtmax = 0.
        for c in '0123456789abcdef':
            sig[i] = c
            for d in '0123456789abcdef':
                sig[i+1] = d
                params['signature'] = ''.join(sig)
                req = requests.get(url, params=params)
                if req:
                    return ''.join(sig)
                else:
                    dt = req.elapsed.total_seconds()
                    print(f'{1000.*dt:.2f} ms')
                    if dt>dtmax:
                        dtmax = dt
                        cmax = c
                        dmax = d
        sig[i]   = cmax
        sig[i+1] = dmax


## ===== MAIN ===== ##
if __name__=='__main__':
    print(f'Serving on port {PORT}...', end=' ')
    httpd = HTTPServer(('', PORT), TimingLeakWebApp)
    httpd_thread = Thread(target=httpd.serve_forever, daemon=True)
    httpd_thread.start()
    print('running.')
    mac = guess_mac()
    print(f'guess  > {mac}')
