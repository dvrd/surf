#!/usr/bin/env python3
"""Characterize the real buffered adapter against owned raw HTTP/TLS peers.

This gate deliberately retains legacy semantics, including methods that ignore
buffered bodies and HEAD custom-request body waiting. It does not infer native
parity from successful legacy runs. No live provider or trust-store mutation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import shutil
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time


class Peer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        connection = self.request
        try:
            if self.server.tls:
                connection = self.server.tls.wrap_socket(connection, server_side=True)
            connection.settimeout(3)
            wire = bytearray()
            while b'\r\n\r\n' not in wire:
                part = connection.recv(4096)
                if not part:
                    return
                wire.extend(part)
                assert len(wire) < 131072
            head, body = wire.split(b'\r\n\r\n', 1)
            lines = head.split(b'\r\n')
            method, target, version = lines[0].decode().split(' ')
            fields = [line.decode() for line in lines[1:]]
            length = next((int(line.split(':', 1)[1]) for line in fields
                           if line.lower().startswith('content-length:')), 0)
            if any(line.lower() == 'expect: 100-continue' for line in fields):
                connection.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
            while len(body) < length:
                part = connection.recv(min(65536, length - len(body)))
                if not part:
                    break
                body.extend(part)
            record = dict(method=method, target=target, version=version,
                          headers=fields, body_hex=body.hex(), declared=length,
                          tls=connection.version() if self.server.tls else None)
            with self.server.lock:
                self.server.records.append(record)
            if target.startswith('/reset'):
                return
            if target.startswith('/slow') or target.startswith('/head-wait'):
                if target.startswith('/head-wait'):
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n')
                time.sleep(.35)
                return
            if target.startswith('/malformed'):
                connection.sendall(b'HTTP/1.1 bad status\r\n\r\n')
                return
            status, payload = b'200 OK', b'RRRR'
            extra = b''
            if target.startswith('/redirect'):
                status, payload = b'307 Temporary Redirect', b''
                extra = b'Location: /must-not-follow\r\n'
            elif target.startswith('/status'):
                status = b'503 Service Unavailable'
            elif target.startswith('/empty'):
                payload = b''
            elif target.startswith('/exact'):
                payload = b'R' * 65536
            elif target.startswith('/oversize'):
                payload = b'R' * 65537
            if target.startswith('/chunked'):
                wire = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nRRRR\r\n0\r\n\r\n'
            elif target.startswith('/eof'):
                wire = b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nRRRR'
            elif target.startswith('/truncated'):
                wire = b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 9\r\n\r\nR'
            else:
                wire = b'HTTP/1.1 ' + status + b'\r\n' + extra
                wire += b'Content-Length: ' + str(len(payload)).encode() + b'\r\nConnection: close\r\n\r\n' + payload
            connection.sendall(wire)
        except (OSError, ssl.SSLError):
            pass
        except Exception as error:
            with self.server.lock:
                self.server.errors.append(repr(error))
        finally:
            connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', type=Path, required=True)
    parser.add_argument('--shared', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--sanitize', choices=['address', 'thread'])
    parser.add_argument('--native', action='store_true', help='Require provider_code zero after native replacement')
    args = parser.parse_args()
    report = dict(passed=False, purpose='legacy public adapter characterization; not native parity',
                  sanitizer=args.sanitize or 'none', native=args.native, cases=[])
    root = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='surf-compatibility-') as directory:
        temp = Path(directory)
        cert, key, binary = temp/'ca.pem', temp/'key.pem', temp/'fixture'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, capture_output=True)
        body_file = temp/'body'; body_file.write_bytes(b'file-extra')
        collection = temp/'shared'
        for name in ['surf', 'http', 'ascii', 'websocket', 'async']:
            source = root.parent if name == 'surf' else args.shared/name
            shutil.copytree(source, collection/name,
                            ignore=shutil.ignore_patterns('.git', '__pycache__'))
        command = [str(args.odin), 'build', str(collection/'surf/tests/testdata/compatibility'),
                   '-collection:shared='+str(collection), '-thread-count:1',
                   '-warnings-as-errors', '-out:'+str(binary)]
        if args.sanitize:
            command += ['-sanitize:'+args.sanitize]
        subprocess.run(command, check=True, timeout=90)
        report['build'] = command
        report['compiler'] = {'path': str(args.odin),
                              'version': subprocess.check_output([str(args.odin), 'version'], text=True).strip(),
                              'sha256': hashlib.sha256(args.odin.read_bytes()).hexdigest()}
        report['runtime_sources'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in sorted(root.parent.glob('*.odin'))}
        report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report['linked_libraries'] = subprocess.check_output(['otool', '-L', str(binary)], text=True)
        peers = []
        for version in [None, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
            peer = Peer(('127.0.0.1', 0), Handler)
            peer.tls = None
            peer.records, peer.errors, peer.lock = [], [], threading.Lock()
            if version:
                peer.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                peer.tls.minimum_version = peer.tls.maximum_version = version
                peer.tls.load_cert_chain(cert, key)
            worker = threading.Thread(target=peer.serve_forever, daemon=True)
            worker.start(); peers.append((peer, worker))
        try:
            def run(name, method='GET', target='/ordinary', body='body', headers=(),
                    file=False, size=4, timeout=1500, tls=0, ca=None):
                peer = peers[tls][0]
                scheme = 'https' if tls else 'http'
                url = f'{scheme}://127.0.0.1:{peer.server_address[1]}{target}'
                command = [str(binary), method, url, str(cert) if tls and ca is None else ca or '',
                           str(body_file) if file else '-', str(size), str(timeout), body,
                           'http' if not tls else 'https', *headers]
                # CURLOPT_PROXY="" must bypass even explicit poisoned ambient values.
                env = dict(os.environ, http_proxy='http://127.0.0.1:1',
                           https_proxy='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1',
                           HTTP_PROXY='http://127.0.0.1:1', HTTPS_PROXY='http://127.0.0.1:1',
                           NO_PROXY='', no_proxy='')
                before = len(peer.records)
                result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=8)
                assert result.returncode == 0, (name, result.stdout, result.stderr)
                assert 'Sanitizer' not in result.stderr, (name, result.stderr)
                assert result.stdout.startswith('{'), (name, result.stdout, result.stderr)
                sent = not (name.startswith('ca-') or '#fragment' in name)
                if sent:
                    cutoff = time.monotonic()+.2
                    while len(peer.records)==before and time.monotonic()<cutoff:
                        time.sleep(.002)
                    assert len(peer.records)==before+1, (name, peer.records[before:])
                row = dict(name=name, result=json.loads(result.stdout),
                           wire=peer.records[before:])
                report['cases'].append(row)
                args.report.write_text(json.dumps(report, indent=2)+'\n')
                return row
            for method in ['GET', 'get', 'POST', 'PUT', 'DELETE', 'PATCH', 'PROPFIND', 'HEAD']:
                row = run('method-'+method, method=method)
                assert row['result']['transport_ok']
                assert row['wire'][0]['method'] == method
                assert row['wire'][0]['body_hex'] == ('626f6479' if method in ['PUT','POST'] else '')
            for method in ['PUT', 'POST', 'DELETE', 'PROPFIND']:
                row = run('file-'+method, method=method, file=True)
                assert row['result']['transport_ok'] and row['result']['file_position'] == 4
                assert row['wire'][0]['body_hex'] == b'file'.hex()
            row = run('file-zero', method='PUT', file=True, size=0)
            assert row['result']['transport_ok'] and row['result']['file_position'] == 0
            assert row['wire'][0]['body_hex'] == ''
            row = run('file-short', method='PUT', file=True, size=20)
            assert not row['result']['transport_ok'] and row['result']['file_position'] == 10
            assert row['result']['phase'] == 'Write' and row['result']['effect'] == 'Unknown'
            row = run('headers', headers=['Host: override.test', 'X-Duplicate: one', 'X-Duplicate: two',
                                    'Accept:', 'X-Suppress:', 'X-Empty;', 'bare'])
            assert row['wire'][0]['headers'] == ['Host: override.test', 'X-Duplicate: one',
                                                'X-Duplicate: two', 'X-Empty:']
            for name, headers in [('host-suppress', ['Host:']),
                                  ('host-duplicate', ['Host: first.test', 'Host: second.test']),
                                  ('type-suppress', ['Content-Type:']),
                                  ('type-empty', ['Content-Type;']),
                                  ('length-override', ['Content-Length: 4'])]:
                run(name, method='POST', headers=headers)
            for method in ['PUT', 'POST']:
                run('empty-'+method, method=method, body='empty')
            for target in ['/a/../b/%2f?q=%2B&empty=', '/a/./b//c', '/a/./b//c#fragment', '?query=only']:
                run('path-'+target, target=target)
            for target in ['/exact', '/oversize', '/chunked', '/eof', '/empty', '/status',
                           '/truncated', '/redirect', '/reset', '/malformed', '/slow', '/head-wait']:
                run('response-'+target, method='HEAD' if target=='/head-wait' else 'POST',
                    target=target, timeout=100 if target in ['/slow','/head-wait'] else 1500)
            for version in [1,2]:
                row = run('tls-'+str(version), tls=version)
                assert row['result']['transport_ok'] and row['result']['status'] == 200
                assert row['wire'][0]['tls'] == ('TLSv1.2' if version==1 else 'TLSv1.3')
            for name, ca in [('missing', str(temp/'missing.pem')), ('malformed', str(body_file))]:
                row = run('ca-'+name, tls=2, ca=ca)
                assert not row['result']['transport_ok'] and not row['wire']
                assert row['result']['phase']=='TLS' and row['result']['effect']=='Not_Sent'
            for peer, _ in peers:
                assert not peer.errors, peer.errors
            for row in report['cases']:
                r = row['result']
                if args.native or r['transport_ok']:
                    assert r['provider_code'] == 0, row
                if r['transport_ok']:
                    assert r['kind']=='None' and r['ok']==(200 <= r['status'] < 300), row
                assert len(row['wire']) <= 1, row
                if row['name'].startswith('response-'):
                    expected = {
                        '/exact': (True,200,65536), '/oversize': (False,200,0),
                        '/chunked': (True,200,4), '/eof': (True,200,4),
                        '/empty': (True,200,0), '/status': (True,503,4),
                        '/truncated': (False,503,0), '/redirect': (True,307,0),
                        '/reset': (False,0,0), '/malformed': (False,0,0),
                        '/slow': (False,0,0), '/head-wait': (False,200,0),
                    }[row['name'][len('response-'):]]
                    assert (r['transport_ok'],r['status'],r['length']) == expected, row
                    if not r['transport_ok'] and r['status']:
                        assert r['effect']=='Response_Received' and r['error_status']==r['status']
                    if row['name'] in ['response-/slow','response-/head-wait']:
                        assert r['phase']=='Deadline' and 50 <= r['elapsed_ms'] < 1000, row
                assert r['all_r']
            assert not any(w['target']=='/must-not-follow' for row in report['cases'] for w in row['wire'])
            report['passed'] = True
        finally:
            for peer, worker in peers:
                peer.shutdown(); peer.server_close(); worker.join(timeout=4)
        report['source_sha256'] = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in [root/'compatibility_loopback.py', root/'testdata/compatibility/main.odin']}
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(passed=report['passed'], cases=len(report['cases']), report=str(args.report))))


if __name__ == '__main__':
    main()
