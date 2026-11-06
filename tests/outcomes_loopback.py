#!/usr/bin/env python3
"""Exercise actual native/curl error paths against owned offline loopback peers."""
import argparse
import collections
import contextlib
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--odin', required=True)
parser.add_argument('--sanitize', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parent
counts = collections.Counter()
lock = threading.Lock()

class Peer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        connection = self.request
        try:
            if getattr(self.server, 'tls', None):
                connection = self.server.tls.wrap_socket(connection, server_side=True)
            connection.settimeout(3)
            wire = bytearray()
            while b'\r\n\r\n' not in wire:
                part = connection.recv(4096)
                if not part:
                    return
                wire.extend(part)
            head, body = wire.split(b'\r\n\r\n', 1)
            length = next((int(line.split(b':', 1)[1]) for line in head.split(b'\r\n')[1:]
                           if line.lower().startswith(b'content-length:')), 0)
            while len(body) < length:
                part = connection.recv(4096)
                if not part:
                    return
                body.extend(part)
            path = head.split(b' ', 2)[1].decode()
            with lock:
                counts[path] += 1
            if path == '/native-redirect':
                connection.sendall(b'HTTP/1.1 307 Temporary Redirect\r\nLocation: /native-redirected-reset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                return
            if path == '/native-unsafe-redirect':
                connection.sendall(b'HTTP/1.1 302 Found\r\nLocation: /never-follow-this-post\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                return
            if path.endswith('reset'):
                return
            if path.endswith('slow'):
                time.sleep(.6)
                return
            if path.endswith('malformed'):
                connection.sendall(b'HTTP/1.1 bad status\r\n\r\n')
            elif path.endswith('large'):
                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n' + b'x' * 65537)
            else:
                connection.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        except (OSError, ssl.SSLError):
            pass
        finally:
            connection.close()

with tempfile.TemporaryDirectory(prefix='surf-outcomes-') as tmp:
    temp = Path(tmp)
    for name in ('server', 'wrong-root'):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(temp / (name + '.key')), '-out', str(temp / (name + '.pem')),
                        '-days', '1', '-subj', '/CN=' + name], check=True, capture_output=True)
    (temp / 'empty-resolv.conf').write_text('# Deliberately no resolver for the native DNS failure fixture.\n')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(temp / 'server.pem', temp / 'server.key')
    with contextlib.ExitStack() as stack:
        peers = []
        for tls in (None, context):
            peer = stack.enter_context(Peer(('127.0.0.1', 0), Handler))
            peer.tls = tls
            thread = threading.Thread(target=peer.serve_forever, daemon=True)
            thread.start()
            stack.callback(peer.shutdown)
            peers.append(peer)
        # Bound but deliberately not listening: the port remains ours and no
        # unrelated process can claim it while refused-connect cases execute.
        refused = stack.enter_context(socket.socket())
        refused.bind(('127.0.0.1', 0))
        binary = temp / 'outcomes.bin'
        command = [args.odin, 'build', str(root / 'testdata/outcomes'), '-thread-count:1',
                   '-warnings-as-errors', '-out:' + str(binary)]
        if args.sanitize:
            command.append('-sanitize:address')
        subprocess.run(command, check=True)
        env = dict(os.environ,
                   SURF_OUTCOME_HTTP='http://127.0.0.1:' + str(peers[0].server_address[1]),
                   SURF_OUTCOME_TLS='https://127.0.0.1:' + str(peers[1].server_address[1]),
                   SURF_OUTCOME_REFUSED='http://127.0.0.1:' + str(refused.getsockname()[1]),
                   SURF_OUTCOME_WRONG_ROOT=str(temp / 'wrong-root.pem'),
                   SURF_OUTCOME_EMPTY_RESOLVER=str(temp / 'empty-resolv.conf'))
        subprocess.run([str(binary)], env=env, check=True, timeout=20)
        expected = {f'/{provider}-{path}': 1 for provider in ('native', 'curl')
                    for path in ('reset', 'large', 'malformed', 'slow')}
        expected['/status'] = 1
        expected.update({'/native-redirect': 1, '/native-redirected-reset': 1, '/native-unsafe-redirect': 1})
        assert dict(counts) == expected, (dict(counts), expected)
print('Only owned loopback peers used; each POST reached the peer exactly once.')
