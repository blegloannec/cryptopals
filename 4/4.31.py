#!/usr/bin/env python3

import os, time
from myhmac import HMAC_SHA1


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
            # ARTIFICIAL DELAY
            # 5 ms is enough (at least for python3 on my computer)
            time.sleep(0.005)
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
    sig = ['0']*40
    for i in range(len(sig)):
        dtmax = 0.
        for c in '0123456789abcdef':
            sig[i] = c
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
        sig[i] = cmax


## ===== MAIN ===== ##
if __name__=='__main__':
    print(f'Serving on port {PORT}...', end=' ', flush=True)
    httpd = HTTPServer(('', PORT), TimingLeakWebApp)
    httpd_thread = Thread(target=httpd.serve_forever, daemon=True)
    httpd_thread.start()
    print('running.')
    mac = guess_mac()
    print(f'guess  > {mac}')
    assert mac is not None  # guess failed
