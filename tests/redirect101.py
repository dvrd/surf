#!/usr/bin/env python3
"""Strict paired physical-copy public Client redirect protocol/lifetime gate.

TLS cutoff first validates a separate GET/200/CL0 warmup on the same physical
first-origin connection. Its logical redirect request then gets an explicit
200 ms caller deadline; every later-hop TLS setup shares that original cutoff.
Warmup traffic is verified separately and never counted as a redirect hop.
"""
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


def required_modes(encrypted):
    return ([method+str(status) for method in ('get','head','post') for status in (301,302,303,307,308)]
            + ['disabled','relative','cross-public','cross-auth','cross-cookie','cross-custom',
               'loop','hopcap','bodycap','cutoff','dns32','cancel','close','handoff-cancel','handoff-close']
            + (['downgrade'] if encrypted else []))


def verify_peer(mode, encrypted, native, peer, label):
    require(peer['mode']==mode and peer['tls']==encrypted, label+' peer case mismatch')
    rows=peer['events']
    warmups=peer.get('warmups') or []
    warmup=encrypted and mode=='cutoff'
    require(native.get('warmup') is warmup, label+' warmup witness')
    if warmup:
        require(len(warmups)==1 and bool(rows), label+' first-origin warmup missing/duplicate')
        w=warmups[0]
        require(w['method']=='GET' and w['path']=='/warmup' and w['body']=='' and
                w['response_status']==200 and w['response_bytes']>0 and w['request_bytes']>0 and
                w['alpn']=='http/1.1' and w['negotiated_tls']==0x304 and
                w['connection_id']==rows[0]['connection_id'], label+' warmup not validated/reused')
    else:
        require(not warmups, label+' unexpected warmup')
    expected=2
    if mode in ('disabled','bodycap','downgrade','cross-auth','cross-cookie','cross-custom','handoff-cancel','handoff-close') or mode in ('post301','post302','post303','head301','head302','head303'):
        expected=1
    if mode in ('loop','hopcap'): expected=6
    if mode=='cutoff':
        expected=len(rows)
        # TLS setup on a later hop consumes the same original total budget;
        # reaching a second HTTP request is not a throughput requirement.
        require(1<=expected<=3, label+' original cutoff must interrupt the multi-hop chain')
        require(native['error']=='Deadline_Failed' and native['phase']=='Deadline' and
                native['status']==302 and native['write_effect'] in ('Unknown','Response_Received') and
                native['elapsed_ms']<350, label+' original total cutoff/context')
        require(rows[0]['response_status']==302 and rows[0]['response_bytes']>0 and
                rows[0]['old_stream_closed'] is True, label+' validated redirect was not retired')
    require(len(rows)==expected, label+' wire count: '+str(len(rows))+' expected '+str(expected))
    require([r['order'] for r in rows]==list(range(1,expected+1)), label+' request ordering')
    require(len({r['connection_id'] for r in rows})==expected, label+' redirect reused physical connection')
    method='POST' if mode.startswith('post') else 'HEAD' if mode.startswith('head') else 'GET'
    for r in rows:
        require(r['request_bytes']>len(r['body']), label+' missing actual request bytes')
        require(r['method']==method and r['body']==('proof-body' if method=='POST' else ''), label+' method/body changed')
        require(r['alpn']==('http/1.1' if encrypted else '') and r['negotiated_tls']==(0x304 if encrypted else 0), label+' negotiated TLS/ALPN mismatch')
        if mode not in ('cancel','close','cutoff') or r['order']<expected:
            require(r['response_bytes']>0, label+' missing actual response bytes')
            if r['response_status']!=200: require(r['old_stream_closed'] is True, label+' client did not close keep-alive redirect stream')
    if mode.startswith('handoff-'): require(native['handoff_callback'] is True, label+' missing causal Redirecting callback')
    if mode=='relative': require(rows[1]['path']=='/final?proof=relative', label+' relative target')
    if mode=='cross-public':
        require(rows[0]['host']!=rows[1]['host'], label+' cross origin not exercised')
        require(rows[1]['headers']['Accept']==['text/plain'], label+' public header not preserved')
    if mode=='dns32':
        require(native['dns_ids_remaining']==32, label+' original32 prepared draw allowance reset')
        require(set(peer['dns_names'])=={'one.redirect.test','two.redirect.test'}, label+' unexpected/absent DNS names')
        require([r['host'].split(':')[0] for r in rows]==['one.redirect.test','two.redirect.test'], label+' DNS hop order')
    else: require(peer['dns_names'] in ([],None), label+' unexpected DNS traffic')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--odin', type=Path, required=True)
    p.add_argument('--core-root', type=Path, required=True)
    p.add_argument('--shared-root', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--sanitizers', nargs='+', choices=['address', 'thread'], default=['address', 'thread'])
    a = p.parse_args()
    compiler, core, shared, report = [x.resolve() for x in (a.odin, a.core_root, a.shared_root, a.report)]
    require(len(a.sanitizers)==2 and set(a.sanitizers)=={"address", "thread"}, "Both distinct sanitizers are required")
    require(len(required_modes(False))==30 and len(required_modes(True))==31, 'Required literal case matrix changed')
    report.parent.mkdir(parents=True, exist_ok=True)
    here = shared / 'surf'
    state = {'passed': False, 'scope': 'public Client redirect composition; owned Go TCP/TLS/DNS, one-worker cap1, no private kernel completion injection; held target and allocator callback accepted-handoff cancel/close',
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
        artifacts = ['tests/async/internal/network_config_test.odin', 'tests/async/internal/redirect_actor_test.odin', 'tests/redirect101.py', 'tests/testdata/redirect101/main.odin', 'tests/testdata/redirect101/peer.go']
        state['fixture_sources_before'] = manifest(here, artifacts)
        helper = compiler.parent/'ci/webtools_consumer_gate.py'
        state['closure_helper_sha256'] = sha(helper)
        spec = importlib.util.spec_from_file_location('exchange_closure', helper)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-redirect28-') as tmp:
            temp = Path(tmp)
            copied = temp/'shared'
            copied.mkdir()
            state['closures'] = {name: copy_closure(gate, name, shared, copied) for name in ('surf/async', 'async/connection')}
            state['copied_files_before'] = manifest(copied)
            state['source_files_before'] = manifest(shared, state['copied_files_before'])
            require(state['copied_files_before'] == state['source_files_before'], 'Physical closure hash mismatch')
            host = temp/'host'
            host.mkdir()
            shutil.copyfile(here/'tests/testdata/redirect101/main.odin', host/'main.odin')
            state['host_sha256'] = sha(host/'main.odin')
            peer = report.parent/'peer'
            shutil.copyfile(here/'tests/testdata/redirect101/peer.go', temp/'peer.go')
            run('peer-build', [go, 'build', '-o', peer, temp/'peer.go'])
            state['peer_sha256'] = sha(here/'tests/testdata/redirect101/peer.go')
            state['artifact_hashes'][str(peer)] = sha(peer)
            require(state['fixture_sources_before']['tests/testdata/redirect101/main.odin']==sha(host/'main.odin'), 'Host source copy mismatch')
            require(state['peer_sha256']==sha(temp/'peer.go'), 'Peer physical source copy mismatch')
            require(state['fixture_sources_before']['tests/testdata/redirect101/peer.go']==state['peer_sha256'], 'Peer source changed during build')
            for sanitizer in a.sanitizers:
                binary = report.parent/('native-'+sanitizer)
                flags = ['-collection:shared='+str(copied), '-warnings-as-errors', '-thread-count:1', '-sanitize:'+sanitizer]
                unit = run('unit-'+sanitizer, [compiler, 'test', copied/'surf/async', *flags,
                    '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_NAMES=redirect28_public_config_and_prestart_handle_lifecycle,network_schema_rejects_forged_normalization_and_invalid_redirect_policy', '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true', '-keep-executable', '-out:'+str(report.parent/('tests-'+sanitizer))])
                require(re.findall(r'Finished (\d+) tests? in ', unit)==['2'] and 'All tests were successful' in unit, 'Redirect unit count mismatch')
                state['artifact_hashes'][str(report.parent/('tests-'+sanitizer))] = sha(report.parent/('tests-'+sanitizer))
                run('host-build-'+sanitizer, [compiler, 'build', host, *flags, '-out:'+str(binary)])
                state['artifact_hashes'][str(binary)] = sha(binary)
                for encrypted in (False, True):
                    modes = required_modes(encrypted)
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
                            require(len(rows)==1, label+' invalid native evidence')
                            native = rows[0]
                            require(native['completed']==1 and native['workers']==1, label+' terminal/worker count')
                            for fact in ('same_handle','terminal_once','cap_one','heap_zero','scope_zero','fd_zero'):
                                require(native[fact] is True, label+' missing '+fact)
                            out, err = proc.communicate(timeout=5)
                            require(proc.returncode==0, label+' peer failed '+out+err)
                            peer_rows = [json.loads(x) for x in out.splitlines() if x.startswith('{')]
                            require(len(peer_rows)==1, label+' independent peer receipt missing')
                            verify_peer(mode, encrypted, native, peer_rows[0], label)
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
        expected = {san+'-'+transport+'-'+mode for san in a.sanitizers for transport in ('tcp','tls') for mode in required_modes(transport=='tls')}
        require(len(expected)==122, 'Required paired matrix changed')
        require(len(state['cells'])==len(expected) and {cell['name'] for cell in state['cells']}==expected, 'Missing or duplicate native matrix cells')
        state['expected_native_cells'] = len(expected)
        state['required_matrix'] = sorted(expected)
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
