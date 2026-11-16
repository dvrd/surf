#!/usr/bin/env python3
"""Darwin local-only bounded setup, cleanup and event-loop isolation checks."""
from staging import copy_closure, test_run, test_files
import argparse
import contextlib
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--odin', required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent

class TCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

class UDP(socketserver.ThreadingUDPServer):
    daemon_threads = True

class Silent(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            self.request.recv(4096)
            self.server.release.wait(2)
        except OSError:
            pass

class Send(socketserver.BaseRequestHandler):
    def handle(self):
        time.sleep(.01)
        self.request.sendall(b'x')

class Secure(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.context.wrap_socket(self.request,server_side=True) as connection:
                connection.settimeout(2)
                connection.recv(1)
        except OSError:
            pass

class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket_ = self.request
        with self.server.lock:
            self.server.requests += 1
        if self.server.answer:
            time.sleep(self.server.delay)
            # Preserve the actual question; answer it with one IPv4 record.
            response = data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+data[12:]
            response += b'\xc0\x0c'+struct.pack('!HHIH',1,1,1,4)+b'\x7f\x00\x00\x01'
            socket_.sendto(response,self.client_address)

@contextlib.contextmanager
def serve(kind, handler):
    with kind(('127.0.0.1',0),handler) as server:
        server.release=threading.Event();server.lock=threading.Lock()
        server.requests=0;server.answer=False;server.delay=0
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.release.set();server.shutdown();thread.join(2)

with tempfile.TemporaryDirectory(prefix='surf-setup-') as temporary:
    temp=Path(temporary)
    binary=temp/'checks'
    test_run([args.odin,'build',str(root/'testdata/setup'),'-thread-count:1','-warnings-as-errors','-sanitize:address','-out:'+str(binary)],check=True)
    test_run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(temp/'key.pem'),'-out',str(temp/'root.pem')],check=True,capture_output=True)
    def run(mode,port,*extra):
        test_run([str(binary),mode,str(port),str(temp/'root.pem'),*map(str,extra)],check=True,timeout=5)
    with serve(UDP,DNS) as dns:
        run('dns',dns.server_address[1])
        run('surf-dns',dns.server_address[1])
        assert dns.requests == 16
        dns.answer=True
        run('resolve',dns.server_address[1])
        assert dns.requests == 24
        run('dns-tiny',dns.server_address[1])
        dns.delay=.025
        with serve(TCP,Silent) as peer:
            run('tls-dns',peer.server_address[1],dns.server_address[1])
    with serve(TCP,Send) as peer:
        run('connect',peer.server_address[1])
    # Reserve then close an owned ephemeral port for refused-connect cleanup.
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1',0));refused=reserved.getsockname()[1]
    run('refuse',refused)
    with serve(TCP,Silent) as peer:
        for mode in ('tls','tls-setup','tls-handshake'):
            run(mode,peer.server_address[1])
    with serve(TCP,Secure) as peer:
        peer.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        peer.context.minimum_version=ssl.TLSVersion.TLSv1_3
        peer.context.maximum_version=ssl.TLSVersion.TLSv1_3
        peer.context.load_cert_chain(temp/'root.pem',temp/'key.pem')
        run('tls-finished',peer.server_address[1])
        run('tls-clear',peer.server_address[1])
        run('tls-finished-configured',peer.server_address[1])
        run('tls-clear-configured',peer.server_address[1])
    completed=14
    # Darwin may reset full-backlog connections instead of delaying SYNs.
    # Queue state can also admit another success; all outcomes must be bounded.
    # The child counts actual successes/failures/timeouts instead of assuming.
    with contextlib.ExitStack() as stack:
        listener=stack.enter_context(socket.socket());listener.bind(('127.0.0.1',0));listener.listen(1)
        full=False
        for _ in range(32):
            pending=stack.enter_context(socket.socket());pending.settimeout(.03)
            try:
                pending.connect(listener.getsockname())
            except (TimeoutError,ConnectionResetError,ConnectionRefusedError):
                full=True;break
        if full:
            run('backlog',listener.getsockname()[1])
            completed+=1
        else:
            print('SKIP backlog: could not saturate owned queue; no timeout verdict claimed')
print(f'{completed} bounded setup scenarios passed (8 repetitions each); local owned peers only')
