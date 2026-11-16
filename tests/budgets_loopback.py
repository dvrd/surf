#!/usr/bin/env python3
"""Owned native/curl budget and transfer recovery with independent HTTP peers."""
from staging import copy_closure, test_run, test_files
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading


class Peer:
    def __init__(self, size, tls_context=None, allow_handshake_failure=False):
        self.size, self.requests, self.errors = size, 0, []
        self.tls_context = tls_context
        self.allow_handshake_failure = allow_handshake_failure
        self.handshake_failures = 0
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                if self.tls_context:
                    try:
                        connection = self.tls_context.wrap_socket(connection, server_side=True)
                    except (ssl.SSLError, ConnectionResetError):
                        connection.close()
                        if not self.allow_handshake_failure:
                            raise
                        self.handshake_failures += 1
                        continue
                with connection:
                    connection.settimeout(4)
                    request = bytearray()
                    while not request.endswith(b'\r\n\r\n'):
                        data = connection.recv(1)
                        assert data and len(request) < 16384
                        request.extend(data)
                    assert request.startswith(b'GET /budget HTTP/1.1\r\n'), request[:80]
                    self.requests += 1
                    head = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(self.size).encode()
                    try:
                        connection.sendall(head + b'\r\n\r\n' + b'B' * self.size)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    assert self.requests <= 32
        except Exception as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.worker.join(timeout=5)
        self.listener.close()
        assert not self.worker.is_alive() and not self.errors, self.errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', required=True, type=Path)
    parser.add_argument('--shared', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--sanitize', choices=['address', 'thread'])
    args = parser.parse_args()
    source = Path(__file__).resolve().parent / 'testdata/budgets'
    report = {'passed': False, 'checks': [], 'sanitizer': args.sanitize or 'none'}
    with tempfile.TemporaryDirectory(prefix='surf-budget-') as directory:
        binary = Path(directory) / 'fixture'
        command = [str(args.odin), 'build', str(source), '-thread-count:1',
                   '-warnings-as-errors', '-collection:shared=' + str(args.shared),
                   '-out:' + str(binary)]
        if args.sanitize:
            command += ['-sanitize:' + args.sanitize]
        test_run(command, check=True, timeout=60)
        report['build'] = command
        report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        test_run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout',
                        str(Path(directory) / 'key.pem'), '-out',
                        str(Path(directory) / 'root.pem')], check=True, capture_output=True)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
        tls_context.load_cert_chain(Path(directory) / 'root.pem', Path(directory) / 'key.pem')
        for mode, scenario, size in [('native', 'retained', 1024), ('curl', 'retained', 1024),
                                     ('native', 'oversize', 65537), ('curl', 'oversize', 65537),
                                     ('curl', 'legacy', 1024), ('curl', 'empty', 0),
                                     ('tls', 'tls-allow', 1024), ('tls', 'tls-deny', 1024)]:
            peer = Peer(size, tls_context if mode == 'tls' else None,
                        allow_handshake_failure=scenario == 'tls-deny')
            try:
                scheme = 'https' if mode == 'tls' else 'http'
                command = [str(binary), mode, f'{scheme}://127.0.0.1:{peer.port}/budget', scenario]
                if mode == 'tls':
                    command += [str(Path(directory) / 'root.pem')]
                result = test_run(command, text=True, capture_output=True, timeout=30)
                assert result.returncode == 0, (mode, scenario, result.stderr, result.stdout)
                assert 'Sanitizer' not in result.stderr, result.stderr
                try:
                    receipt = json.loads(result.stdout)
                except ValueError as error:
                    raise AssertionError((mode, scenario, result.stdout, result.stderr)) from error
                assert receipt['calls'] == peer.requests, (receipt, peer.requests)
                assert receipt['peak'] <= receipt['limit']
                report['checks'].append(dict(mode=mode, scenario=scenario, receipt=receipt,
                                             command=command, returncode=result.returncode))
            finally:
                peer.close()
            assert peer.handshake_failures == (1 if scenario == 'tls-deny' else 0)
    report['passed'] = len(report['checks']) == 8
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks'])}))


if __name__ == '__main__':
    main()
