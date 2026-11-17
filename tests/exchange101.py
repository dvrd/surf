#!/usr/bin/env python3
"""Physical-copy HTTP1 exchange and public TLS idle-checkout gate."""
from staging import copy_closure, test_run, test_files
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import select
import shutil
import signal
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def manifest(root, names=None):
    root = Path(root)
    if names is None:
        names = sorted(str(p.relative_to(root)) for p in root.rglob('*')
                       if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts)
    result = {}
    for name in names:
        p = root / name
        require(p.is_file() and not p.is_symlink(), 'Nonphysical closure: ' + str(p))
        result[name] = sha(p)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--odin', type=Path, required=True)
    p.add_argument('--core-root', type=Path, required=True)
    p.add_argument('--shared-root', type=Path, required=True)
    p.add_argument('--require-idle-policy', action='store_true')
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--sanitizers', nargs='+', choices=['address', 'thread'], default=['address', 'thread'])
    a = p.parse_args()
    compiler, core, shared, report = [x.resolve() for x in (a.odin, a.core_root, a.shared_root, a.report)]
    require(len(a.sanitizers)==len(set(a.sanitizers)), "Duplicate sanitizer selection")
    if a.require_idle_policy:
        require(set(a.sanitizers)=={"address", "thread"}, "Full idle matrix requires both sanitizers")
    report.parent.mkdir(parents=True, exist_ok=True)
    here = shared / 'surf'
    state = {'passed': False, 'scope': 'owned literal/fake byte streams and native numeric-loopback HTTP1/TLS13 exchange; no Client/session actor, DNS or cross-platform certification',
             'commands': [], 'cells': [], 'native_execution_count': 0, 'selected_sanitizers': a.sanitizers, 'artifact_hashes': {}}
    env = dict(os.environ, ODIN_ROOT=str(core), GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0')
    env['PATH'] = '/opt/homebrew/opt/llvm@22/bin:' + env.get('PATH', '')
    env['GOCACHE'] = str(report.parent / 'go-cache')
    for key in list(env):
        if key.startswith(('AWS_', 'GOOGLE_', 'GCLOUD_', 'AZURE_')):
            del env[key]

    def run(name, command, timeout=180):
        command = [str(x) for x in command]
        start = time.monotonic()
        cell = {'name': name, 'command': command}
        state['commands'].append(cell)
        try:
            done = test_run(command, env=env, capture_output=True, text=True, timeout=timeout)
            text = done.stdout + done.stderr
            cell['returncode'] = done.returncode
            cell['stdout'] = done.stdout
            cell['stderr'] = done.stderr
        except (OSError, subprocess.TimeoutExpired) as error:
            text = str(error)
            cell.update(returncode=None, error=type(error).__name__)
        log = report.parent / (name + '.log')
        log.write_text(text)
        cell.update(log=str(log), log_sha256=sha(log), seconds=time.monotonic()-start)
        require(cell['returncode'] == 0, name + ' failed: ' + str(log))
        require('+++ leak' not in text and '+++ bad free' not in text, name + ' ownership diagnostic')
        return text

    def stop(proc):
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            return proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            return proc.communicate(timeout=5)

    try:
        require((core/'core/crypto/tls/async_idle.odin').is_file(), 'Explicit core lacks public TLS idle classifier')
        require((shared/'async/socket.odin').is_file(), 'Explicit shared lacks public nonconsuming stream probe')
        go = Path(shutil.which('go', path=env['PATH'])).resolve()
        state['go'] = {'path': str(go), 'sha256': sha(go), 'version': run('go-version', [go, 'version']).strip()}
        state['compiler'] = {'path': str(compiler), 'sha256': sha(compiler), 'version': run('compiler-version', [compiler, 'version']).strip(), 'root': str(core)}
        stdnames = sorted(str(x.relative_to(core)) for folder in ('base', 'core', 'vendor') for x in (core/folder).rglob('*') if x.is_file() and x.suffix in ('.odin', '.h', '.c', '.s', '.S'))
        state['standard_sources_before'] = manifest(core, stdnames)
        state['runner_sha256'] = sha(__file__)
        artifacts = ['tests/async/exchange/internal/exchange_test.odin', 'tests/exchange101.py', 'tests/testdata/exchange101/main.odin', 'tests/testdata/exchange101/peer.go']
        state['fixture_sources_before'] = manifest(here, artifacts)
        helper = compiler.parent/'ci/webtools_consumer_gate.py'
        state['closure_helper_sha256'] = sha(helper)
        spec = importlib.util.spec_from_file_location('exchange_closure', helper)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-exchange-') as tmp:
            temp = Path(tmp)
            copied = temp/'shared'
            copied.mkdir()
            state['closures'] = {name: copy_closure(gate, name, shared, copied) for name in ('surf/async/exchange', 'async/connection')}
            state['copied_files_before'] = manifest(copied)
            state['source_files_before'] = manifest(shared, state['copied_files_before'])
            require(state['copied_files_before'] == state['source_files_before'], 'Physical closure hash mismatch')
            host = temp/'host'
            host.mkdir()
            shutil.copyfile(here/'tests/testdata/exchange101/main.odin', host/'main.odin')
            state['host_sha256'] = sha(host/'main.odin')
            peer = report.parent/'peer'
            run('peer-build', ['go', 'build', '-o', peer, here/'tests/testdata/exchange101/peer.go'])
            state['peer_sha256'] = sha(here/'tests/testdata/exchange101/peer.go')
            state['artifact_hashes'][str(peer)] = sha(peer)
            require(state['fixture_sources_before']['tests/testdata/exchange101/main.odin']==sha(host/'main.odin'), 'Host source copy mismatch')
            require(state['fixture_sources_before']['tests/testdata/exchange101/peer.go']==state['peer_sha256'], 'Peer source changed during build')
            for sanitizer in a.sanitizers:
                binary = report.parent/('native-'+sanitizer)
                flags = ['-collection:shared='+str(copied), '-warnings-as-errors', '-thread-count:1', '-sanitize:'+sanitizer]
                unit = run('unit-'+sanitizer, [compiler, 'test', copied/'surf/async/exchange', *flags,
                    '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true', '-keep-executable', '-out:'+str(report.parent/('tests-'+sanitizer))])
                require(re.findall(r'Finished (\d+) tests? in ', unit)==['17'] and 'All tests were successful' in unit, 'Exchange aggregate count mismatch')
                state['artifact_hashes'][str(report.parent/('tests-'+sanitizer))] = sha(report.parent/('tests-'+sanitizer))
                run('host-build-'+sanitizer, [compiler, 'build', host, *flags, '-out:'+str(binary)])
                state['artifact_hashes'][str(binary)] = sha(binary)
                for encrypted in (False, True):
                    modes = ['healthy', 'fragmented', 'same-read', 'separate', 'partial', 'close']
                    if encrypted:
                        modes += ['keyupdate', 'keyupdate-inline']
                    for mode in modes:
                        label = sanitizer+'-'+('tls' if encrypted else 'tcp')+'-'+mode
                        directory = temp/label
                        command = [str(peer), '-mode', mode, '-dir', str(directory)] + (['-tls'] if encrypted else [])
                        proc = subprocess.Popen(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                        try:
                            require(select.select([proc.stdout], [], [], 10)[0], label+' readiness timeout')
                            endpoint = proc.stdout.readline().strip()
                            require(endpoint.startswith('127.0.0.1:'), label+' invalid endpoint '+endpoint)
                            output = run(label, [binary, endpoint, mode, 'tls' if encrypted else 'tcp', directory], timeout=25)
                            state['native_execution_count'] += 1
                            rows = [json.loads(x) for x in output.splitlines() if x.startswith('{')]
                            require(len(rows)==2 and rows[1]=={'heap_zero': True}, label+' invalid native evidence')
                            native = rows[0]
                            healthy = mode in ('healthy', 'fragmented', 'keyupdate-inline')
                            require(native['completed']==(2 if healthy else 1), label+' request count')
                            require(native['old_cutoff_expired'] is True, label+' did not cross old A cutoff')
                            if healthy:
                                require(native['idle']=='Ready' and native['probe']=='Empty' and native['close_error']=='None', label+' unsafe checkout')
                            else:
                                require(native['probe']!='Empty' or native['idle']!='Ready', label+' contaminated checkout')
                            out, err = proc.communicate(timeout=5)
                            require(proc.returncode==0, label+' peer failed '+out+err)
                            peer_rows = [json.loads(x) for x in out.splitlines() if x.startswith('{')]
                            require(len(peer_rows)==1 and peer_rows[0]['requests']==native['completed'], label+' independent peer order mismatch')
                            if mode=='keyupdate-inline':
                                require(peer_rows[0]['key_updates']==peer_rows[0]['client_key_updates']==1, label+' missing actual reciprocal KeyUpdate')
                                require(peer_rows[0]['manual_sequences']==[0, 0, 1], label+' unexpected independent record sequence')
                            (report.parent/(label+'-peer.log')).write_text(out+err)
                            require(sha(binary)==state['artifact_hashes'][str(binary)] and sha(peer)==state['artifact_hashes'][str(peer)], label+' binary changed during run')
                            state['cells'].append({'name': label, 'native': native, 'peer': peer_rows[0], 'passed': True})
                        finally:
                            out, err = stop(proc)
                            peer_log = report.parent/(label+'-peer.log')
                            if not peer_log.exists():
                                peer_log.write_text(out+err)
            state['copied_files_after'] = manifest(copied)
            state['source_files_after'] = manifest(shared, state['copied_files_before'])
            require(state['copied_files_before']==state['copied_files_after']==state['source_files_after'], 'Closure changed during execution')
        state['fixture_sources_after'] = manifest(here, artifacts)
        require(state['fixture_sources_before']==state['fixture_sources_after'], 'Fixture source changed during execution')
        state['standard_sources_after'] = manifest(core, stdnames)
        require(state['standard_sources_before']==state['standard_sources_after'], 'Core sources changed during execution')
        require(state['runner_sha256']==sha(__file__), 'Gate changed during execution')
        require(state['compiler']['sha256']==sha(compiler) and state['go']['sha256']==sha(go) and state['closure_helper_sha256']==sha(helper), 'Toolchain/helper changed during execution')
        state['artifact_hashes_after'] = {name: sha(name) for name in state['artifact_hashes']}
        require(state['artifact_hashes']==state['artifact_hashes_after'], 'Executable artifact changed during execution')
        expected = {san+'-'+transport+'-'+mode for san in a.sanitizers for transport, modes in [('tcp', ['healthy','fragmented','same-read','separate','partial','close']), ('tls', ['healthy','fragmented','same-read','separate','partial','close','keyupdate','keyupdate-inline'])] for mode in modes}
        require(len(state['cells'])==len(expected) and {cell['name'] for cell in state['cells']}==expected, 'Missing or duplicate native matrix cells')
        state['expected_native_cells'] = len(expected)
        if a.require_idle_policy:
            require(len(expected)==28 and state['native_execution_count']==28, 'Full idle matrix requires 28 actual unique cells')
        state['log_hashes'] = {str(path): sha(path) for path in sorted(report.parent.glob('*.log'))}
        state['passed'] = True
    except Exception as error:
        state['failure'] = str(error)
        raise
    finally:
        report.write_text(json.dumps(state, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'passed': True, 'native_execution_count': state['native_execution_count'], 'report': str(report)}))


if __name__ == '__main__':
    main()
