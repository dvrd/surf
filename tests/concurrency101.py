#!/usr/bin/env python3
"""Required paired public Client producer/result/shutdown concurrency gate."""
from staging import copy_closure, test_run, test_files
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def manifest(root, names=None):
    root = Path(root)
    names = names if names is not None else sorted(str(p.relative_to(root)) for p in root.rglob('*')
              if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts)
    result = {}
    for name in names:
        p = root/name
        require(p.is_file() and not p.is_symlink(), 'Nonphysical source '+str(p))
        result[name] = sha(p)
    return result


def verify(native, peer, mode, encrypted):
    require(native['mode'] == peer['mode'] == mode and native['tls'] == peer['tls'] == encrypted, 'Fixture identity')
    require(native['workers'] == 1 and native['producer_threads'] == 4 and native['consumer_threads'] == 2, 'Actual thread configuration')
    require(all(native[k] is True for k in ('heap_zero', 'scope_zero', 'fd_zero')), 'Physical cleanup')
    records, wire = native['records'], peer['requests']
    require(native['accepted'] == native['completed'] == len(records), 'One terminal per accepted request')
    ids = [r['id'] for r in records]
    wire_ids = [r['id'] for r in wire]
    require(len(ids) == len(set(ids)) and len(wire_ids) == len(set(wire_ids)), 'Duplicate acceptance or replay')
    require(set(wire_ids) <= set(ids) and 0 < peer['connections'] <= 2 and 0 < peer['peak'] <= 2, 'Bounded actual peer sockets')
    for row in wire:
        require(row['method'] == 'POST' and row['path'] == '/work/'+str(row['id']) and row['body'] == str(row['id']), 'Original cloned request bytes')
        require(row['tls_version'] == (772 if encrypted else 0) and row['alpn'] == ('http/1.1' if encrypted else ''), 'Authenticated protocol')
    if mode == 'success':
        require(set(ids) == set(wire_ids) == set(range(64)), 'Complete literal request identity set')
        require(native['late_response'] is True and native['runtime_gone_before_results'] is False, 'Detached response ownership')
        by_id = {r['id']: r for r in wire}
        require(all(r['kind'] == 'None' and r['connection'] == by_id[r['id']]['connection'] for r in records), 'Response peer identity')
    else:
        require(0 < len(records) <= 8 and wire and native['runtime_gone_before_results'] is True, 'Actual IO shutdown with finite queued work')
        require(all(r['kind'] == 'IO_Failed' and r['phase'] == 'Cancellation' and r['transport'] == 'Cancelled' for r in records), 'Cancellation terminal classification')
    return {'native': native, 'peer': peer}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('odin', 'core-root', 'shared-root', 'report'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    compiler, core, shared, report = [p.resolve() for p in (args.odin, args.core_root, args.shared_root, args.report)]
    report.parent.mkdir(parents=True, exist_ok=True)
    state = {'passed': False, 'scope': 'Real public Client concurrent producer/poll/direct-take and runtime shutdown, with independent peer bytes/IDs and late Response; no performance claim', 'commands': [], 'cells': [], 'skipped': [], 'native_execution_count': 0}
    env = dict(os.environ, ODIN_ROOT=str(core), GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0')
    env['PATH'] = '/opt/homebrew/opt/llvm@22/bin:'+env.get('PATH', '')
    env['GOCACHE'] = str(report.parent/'go-cache')
    for key in list(env):
        if key.startswith(('AWS_', 'GOOGLE_', 'GCLOUD_', 'AZURE_')) or key == 'LINEAR_API':
            del env[key]

    def run(label, command, timeout=120):
        command = list(map(str, command));started = time.monotonic()
        p = test_run(command, env=env, text=True, capture_output=True, timeout=timeout)
        log = report.parent/(label+'.log');log.write_text(p.stdout+p.stderr)
        state['commands'].append({'name': label, 'command': command, 'returncode': p.returncode, 'log': str(log), 'log_sha256': sha(log), 'seconds': time.monotonic()-started})
        require(p.returncode == 0, 'Failed '+str(log))
        require('+++ leak' not in log.read_text() and '+++ bad free' not in log.read_text(), 'Ownership diagnostic '+str(log))
        return p.stdout+p.stderr

    try:
        go = Path(shutil.which('go', path=env['PATH'])).resolve()
        state['compiler'] = {'path': str(compiler), 'sha256': sha(compiler), 'version': run('compiler-version', [compiler, 'version']).strip()}
        state['go'] = {'path': str(go), 'sha256': sha(go), 'version': run('go-version', [go, 'version']).strip()}
        standard = sorted(str(p.relative_to(core)) for folder in ('base', 'core', 'vendor') for p in (core/folder).rglob('*') if p.is_file() and p.suffix in ('.odin', '.c', '.h', '.s', '.S'))
        state['core_sources_before'] = manifest(core, standard)
        artifacts = ['tests/async/internal/concurrency_test.odin', 'tests/concurrency101.py', 'tests/testdata/concurrency101/main.odin', 'tests/testdata/concurrency101/peer.go']
        state['fixtures_before'] = manifest(shared/'surf', artifacts)
        names = re.findall(r'@\(test\)\s*(\w+)\s*::', (shared/'surf/tests/async/internal/concurrency_test.odin').read_text())
        require(len(names) == 2, 'Exact public concurrency unit aggregates')
        helper = compiler.parent/'ci/webtools_consumer_gate.py';state['helper_sha256'] = sha(helper)
        spec = importlib.util.spec_from_file_location('concurrency101_closure', helper)
        gate = importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-concurrency-') as tmp:
            temp = Path(tmp);copied = temp/'shared';copied.mkdir()
            state['closure'] = copy_closure(gate, 'surf/async', shared, copied)
            state['copied_sources_before'] = manifest(copied);state['source_sources_before'] = manifest(shared, state['copied_sources_before'])
            require(state['copied_sources_before'] == state['source_sources_before'], 'Physical copy mismatch')
            host = temp/'host';host.mkdir();shutil.copyfile(shared/'surf/tests/testdata/concurrency101/main.odin', host/'main.odin')
            peer_source = temp/'peer.go';shutil.copyfile(shared/'surf/tests/testdata/concurrency101/peer.go', peer_source)
            peer = report.parent/'peer';run('peer-build', [go, 'build', '-o', peer, peer_source]);run('peer-vet', [go, 'vet', peer_source])
            state['artifact_hashes'] = {str(peer): sha(peer)}
            for san in ('address', 'thread'):
                flags = ['-collection:shared='+str(copied), '-warnings-as-errors', '-thread-count:1', '-sanitize:'+san]
                unit = report.parent/('unit-'+san)
                output = run('unit-'+san, [compiler, 'test', copied/'surf/async', *flags, '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true', '-define:ODIN_TEST_NAMES='+','.join(names), '-keep-executable', '-out:'+str(unit)])
                require(re.findall(r'Finished (\d+) tests? in ', output) == ['2'], 'Actual unit count')
                require('producer_threads=4 attempts=256 accepted=8 consumer_threads=4 terminal_once=true' in output and 'shutdown_during_clone_callback=true producers=4 seeded=1' in output, 'Actual public concurrency evidence')
                state['artifact_hashes'][str(unit)] = sha(unit)
                binary = report.parent/('native-'+san);run('build-'+san, [compiler, 'build', host, *flags, '-out:'+str(binary)]);state['artifact_hashes'][str(binary)] = sha(binary)
                run('linked-'+san, ['otool', '-L', binary])
                for encrypted in (False, True):
                    for mode in ('success', 'shutdown'):
                        label = san+'-'+('tls' if encrypted else 'tcp')+'-'+mode;directory = temp/label
                        proc = subprocess.Popen([str(peer), '-dir', str(directory), '-mode', mode]+(['-tls'] if encrypted else []), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                        ready = '';peer_log = report.parent/(label+'-peer.log')
                        try:
                            require(select.select([proc.stdout], [], [], 8)[0], 'Peer readiness timeout')
                            ready = proc.stdout.readline();endpoint = ready.strip();require(endpoint.startswith('127.0.0.1:'), 'Owned endpoint')
                            state['native_execution_count'] += 1
                            output = run(label, [binary, endpoint, mode, 'tls' if encrypted else 'tcp', directory], 30)
                            stdout, stderr = proc.communicate(timeout=5);peer_log.write_text(ready+stdout+stderr);require(proc.returncode == 0, 'Peer failure '+label)
                            proof = verify(json.loads(output), json.loads(stdout), mode, encrypted)
                            state['cells'].append({'name': label, 'passed': True, **proof})
                        finally:
                            if proc.poll() is None:
                                os.killpg(proc.pid, signal.SIGTERM)
                            stdout, stderr = proc.communicate(timeout=5)
                            if not peer_log.exists():
                                peer_log.write_text(ready+stdout+stderr)
            state['copied_sources_after'] = manifest(copied);state['source_sources_after'] = manifest(shared, state['copied_sources_before'])
            require(state['copied_sources_before'] == state['copied_sources_after'] == state['source_sources_after'], 'Source/copy changed')
        state['fixtures_after'] = manifest(shared/'surf', artifacts);state['core_sources_after'] = manifest(core, standard)
        require(state['fixtures_before'] == state['fixtures_after'] and state['core_sources_before'] == state['core_sources_after'], 'Fixture/core changed')
        state['artifact_hashes_after'] = {p: sha(p) for p in state['artifact_hashes']}
        require(state['artifact_hashes'] == state['artifact_hashes_after'], 'Binary changed')
        require(state['compiler']['sha256'] == sha(compiler) and state['go']['sha256'] == sha(go) and state['helper_sha256'] == sha(helper), 'Toolchain changed')
        expected = {san+'-'+transport+'-'+mode for san in ('address', 'thread') for transport in ('tcp', 'tls') for mode in ('success', 'shutdown')}
        require(len(state['cells']) == state['native_execution_count'] == 8 and {c['name'] for c in state['cells']} == expected, 'Missing or duplicate required cells')
        state['log_hashes'] = {str(p): sha(p) for p in report.parent.glob('*.log')};state['passed'] = True
    except Exception as error:
        state['failure'] = str(error)
        raise
    finally:
        report.write_text(json.dumps(state, indent=2)+'\n')
    print(json.dumps({'passed': state['passed'], 'native_cells': len(state['cells']), 'report': str(report)}))


if __name__ == '__main__':
    main()
