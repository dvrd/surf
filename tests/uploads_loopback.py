#!/usr/bin/env python3
"""Verify native, bounded-memory TCP/TLS uploads with owned local fixtures."""
from staging import copy_closure, test_run, test_files
import argparse
import collections
import contextlib
import hashlib
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
records = []
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
            connection.settimeout(25)
            wire = bytearray()
            while b'\r\n\r\n' not in wire:
                part = connection.recv(4096)
                if not part:
                    return
                wire.extend(part)
            head, body = wire.split(b'\r\n\r\n', 1)
            method, path, _ = head.split(b'\r\n', 1)[0].decode().split(' ')
            lengths = [int(line.split(b':', 1)[1]) for line in head.split(b'\r\n')[1:]
                       if line.lower().startswith(b'content-length:')]
            assert len(lengths) == 1
            length = lengths[0]
            if path == '/stall':
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                with lock:
                    records.append((method, path, length, len(body), None))
                time.sleep(.8)
                return
            digest = hashlib.sha256()
            digest.update(body)
            consumed = len(body)
            while consumed < length:
                part = connection.recv(min(65536, length - consumed))
                if not part:
                    break
                digest.update(part)
                consumed += len(part)
            with lock:
                records.append((method, path, length, consumed, digest.hexdigest()))
            if consumed != length:
                assert path == '/short'
                return
            status = b'307 Temporary Redirect' if path == '/redirect' else b'200 OK'
            location = b'Location: /must-not-replay\r\n' if path == '/redirect' else b''
            connection.sendall(b'HTTP/1.1 ' + status + b'\r\n' + location + b'Content-Length: 2\r\nConnection: close\r\n\r\nok')
        except (OSError, ssl.SSLError):
            pass
        finally:
            connection.close()

with tempfile.TemporaryDirectory(prefix='surf-native-upload-') as tmp:
    temp = Path(tmp)
    (temp / 'openssl.cnf').write_text('''[req]
distinguished_name=dn
x509_extensions=v3
prompt=no
[dn]
CN=localhost
[v3]
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage=serverAuth
''')
    test_run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
                    '-keyout', str(temp / 'server.key'), '-out', str(temp / 'server.pem'),
                    '-days', '1', '-config', str(temp / 'openssl.cnf')], check=True, capture_output=True)
    with (temp / 'upload.bin').open('wb') as output:
        for _ in range(65 * 16):
            output.write(b'Z' * 65536)
        output.write(b'extra')
    (temp / 'short.bin').write_bytes(b'ZZ')
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
        binary = temp / 'upload-tests.bin'
        command = [args.odin, 'build', str(root / 'testdata/uploads'), '-thread-count:1',
                   '-warnings-as-errors', '-out:' + str(binary)]
        if args.sanitize:
            command.append('-sanitize:address')
        test_run(command, check=True)
        env = dict(os.environ,
                   SURF_UPLOAD_HTTP='http://127.0.0.1:' + str(peers[0].server_address[1]),
                   SURF_UPLOAD_TLS='https://127.0.0.1:' + str(peers[1].server_address[1]),
                   SURF_UPLOAD_FILE=str(temp / 'upload.bin'),
                   SURF_UPLOAD_SHORT=str(temp / 'short.bin'),
                   SURF_UPLOAD_ROOT=str(temp / 'server.pem'))
        test_run([str(binary)], env=env, check=True, timeout=45)
        expected = {
            '/put': ('PUT', 65 * 1024 * 1024), '/post': ('POST', 17),
            '/delete': ('DELETE', 0), '/prefix': ('PUT', 3), '/redirect': ('POST', 17),
            '/short': ('PUT', 3), '/stall': ('PUT', 65 * 1024 * 1024),
            '/tls-put': ('PUT', 2 * 1024 * 1024), '/tls-post': ('POST', 17), '/tls-delete': ('DELETE', 9),
        }
        assert collections.Counter(row[1] for row in records) == collections.Counter(expected.keys()), records
        for method, path, declared, consumed, digest in records:
            assert (method, declared) == expected[path]
            if path == '/stall':
                continue
            if path == '/short':
                assert consumed == 2
            else:
                assert consumed == declared
            reference = hashlib.sha256()
            remaining = consumed
            while remaining:
                chunk = min(65536, remaining)
                reference.update(b'Z' * chunk)
                remaining -= chunk
            assert digest == reference.hexdigest()
print('Methods, declared lengths, SHA-256 bodies, prefix cursor and no redirect replay verified.')
