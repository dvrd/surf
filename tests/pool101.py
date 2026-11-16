#!/usr/bin/env python3
"""Source-bound public pool identity, framing and retirement composition gate."""
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
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--cases', nargs='+', choices=['framing','framing-fragmented','host-alias','ports','clients','idle','maxage','stale','partial','separate','peer-close','scheme','trust','alpn','keyupdate','keyupdate-inline','wrong-host'])
    p.add_argument('--sanitizers', nargs='+', choices=['address', 'thread'], default=['address', 'thread'])
    a = p.parse_args()
    compiler, core, shared, report = [x.resolve() for x in (a.odin, a.core_root, a.shared_root, a.report)]
    require(len(a.sanitizers)==len(set(a.sanitizers)), "Duplicate sanitizer selection")
    require(a.cases is None or len(a.cases)==len(set(a.cases)), "Duplicate case selection")
    report.parent.mkdir(parents=True, exist_ok=True)
    here = shared / 'surf'
    fixtures = Path(__file__).resolve().parent
    state = {'passed': False, 'scope': 'public Client identity/trust/ALPN isolation, literal HTTP1 framing, stale/partial/KeyUpdate retirement and Idle/maxage composition; no redirects or platform/performance certification',
             'commands': [], 'cells': [], 'native_execution_count': 0, 'selected_sanitizers': a.sanitizers, 'selected_cases': a.cases, 'artifact_hashes': {}}
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
        artifacts = ['pool101.py', 'testdata/pool101/main.odin', 'testdata/pool101/peer.go']
        state['fixture_sources_before'] = manifest(fixtures, artifacts)
        helper = compiler.parent/'ci/webtools_consumer_gate.py'
        state['closure_helper_sha256'] = sha(helper)
        spec = importlib.util.spec_from_file_location('exchange_closure', helper)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-pool29-') as tmp:
            temp = Path(tmp)
            copied = temp/'shared'
            copied.mkdir()
            state['closures'] = {name: copy_closure(gate, name, shared, copied) for name in ('surf/async', 'async/connection')}
            state['copied_files_before'] = manifest(copied)
            state['source_files_before'] = manifest(shared, state['copied_files_before'])
            require(state['copied_files_before'] == state['source_files_before'], 'Physical closure hash mismatch')
            host = temp/'host'
            host.mkdir()
            shutil.copyfile(fixtures/'testdata/pool101/main.odin', host/'main.odin')
            state['host_sha256'] = sha(host/'main.odin')
            peer = report.parent/'peer'
            run('peer-build', ['go', 'build', '-o', peer, fixtures/'testdata/pool101/peer.go'])
            state['peer_sha256'] = sha(fixtures/'testdata/pool101/peer.go')
            state['artifact_hashes'][str(peer)] = sha(peer)
            require(state['fixture_sources_before']['testdata/pool101/main.odin']==sha(host/'main.odin'), 'Host source copy mismatch')
            require(state['fixture_sources_before']['testdata/pool101/peer.go']==state['peer_sha256'], 'Peer source changed during build')
            for sanitizer in a.sanitizers:
                binary = report.parent/('native-'+sanitizer)
                flags = ['-collection:shared='+str(copied), '-warnings-as-errors', '-thread-count:1', '-sanitize:'+sanitizer]
                run('host-build-'+sanitizer, [compiler, 'build', host, *flags, '-out:'+str(binary)])
                state['artifact_hashes'][str(binary)] = sha(binary)
                for encrypted in (False, True):
                    modes = ['framing','framing-fragmented','host-alias','ports','clients','idle','maxage','stale','partial','separate','peer-close']
                    if encrypted:
                        modes += ['scheme','trust','alpn','keyupdate','keyupdate-inline','wrong-host']
                    if a.cases is not None:
                        modes = [mode for mode in modes if mode in a.cases]
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
                            for fact in ('heap_zero','scope_zero','fd_zero'):
                                require(native[fact] is True, label+' missing '+fact)
                            out, err = proc.communicate(timeout=5)
                            require(proc.returncode==0, label+' peer failed '+out+err)
                            peer_rows = [json.loads(x) for x in out.splitlines() if x.startswith('{')]
                            require(len(peer_rows)==1, label+' peer summary missing')
                            peer_row = peer_rows[0]
                            events = peer_row['events']
                            require(len(events)==peer_row['requests'], label+' inconsistent peer events')
                            require(all(e['alpn']==('http/1.1' if e['secure'] else '') for e in events), label+' actual negotiated ALPN')
                            if mode.startswith('framing'):
                                require(native['completed']==19 and native['framing_cases']==19, label+' framing aggregate count')
                                expected_paths = ['/fixed','/zero','/head','/204','/304','/chunked','/interim','/http10','/post','/close','/http10-close','/connection-close','/eof','/truncated','/malformed','/badchunk','/101','/surplus','/last']
                                require([e['path'] for e in events]==expected_paths, label+' request path/order oracle')
                                require(len({e['connection'] for e in events[:10]})==1, label+' reusable prefix did not reuse')
                                require(all(events[i]['connection']!=events[i-1]['connection'] for i in range(10,19)), label+' retired framing connection reused')
                                require(events[2]['method']=='HEAD' and events[8]['method']=='POST' and events[8]['body']=='payload', label+' method/body oracle')
                            elif mode in ('idle','maxage'):
                                require(native['completed']==2 and [e['path'] for e in events]==['/A','/B'], label+' timer requests')
                                require(events[0]['connection']!=events[1]['connection'], label+' expired session reused')
                                require(0<=native['timer_ns']<1_000_000_000, label+' retirement was not before independent 10s timer')
                            elif mode in ('stale','peer-close','partial','separate','keyupdate'):
                                require(native['completed']==3 and native['failures']==1, label+' retired checkout terminal count')
                                require([e['path'] for e in events]==['/A','/C'] and events[0]['connection']!=events[1]['connection'], label+' ambiguous request replay/contamination')
                                if mode=='keyupdate':
                                    require(peer_row['key_updates']==1 and peer_row['client_key_updates']==0, label+' queued KeyUpdate oracle')
                            elif mode=='keyupdate-inline':
                                require(native['completed']==2 and [e['path'] for e in events]==['/A','/B'], label+' KeyUpdate requests')
                                require(events[0]['connection']==events[1]['connection'] and peer_row['key_updates']==peer_row['client_key_updates']==1, label+' reciprocal KeyUpdate/reuse oracle')
                            elif mode in ('host-alias','ports','scheme','clients'):
                                require(native['completed']==3 and [e['path'] for e in events]==['/A','/B','/C'], label+' identity requests')
                                require(events[0]['connection']==events[2]['connection']!=events[1]['connection'], label+' origin/client identity crossed')
                                if mode=='host-alias':
                                    require([e['host'].split(':')[0].lower() for e in events]==['a.pool.test','b.pool.test','a.pool.test'], label+' hostname identity')
                                    if encrypted:
                                        require([e['sni'] for e in events]==['a.pool.test','b.pool.test','a.pool.test'], label+' URL-derived authenticated hostname')
                                if mode=='ports':
                                    require(events[0]['host']==events[2]['host']!=events[1]['host'], label+' port identity')
                                if mode=='scheme':
                                    require([e['secure'] for e in events]==[True,False,True] and len({e['host'] for e in events})==1, label+' same authority scheme identity')
                            elif mode in ('trust','wrong-host','alpn'):
                                require(native['completed']==(2 if mode=='alpn' else 3), label+' rejected identity completion count')
                                require([e['path'] for e in events]==['/A','/C'] and events[0]['connection']==events[1]['connection'], label+' incompatible authentication obtained data')
                                if mode=='alpn':
                                    require(native['rejected']==1 and peer_row['connections']==1, label+' unsupported ALPN was negotiated')
                                else:
                                    require(native['failures']==1 and peer_row['handshake_errors']>=1 and peer_row['connections']==2, label+' no actual failed independent authentication')
                            (report.parent/(label+'-peer.log')).write_text(out+err)
                            require(sha(binary)==state['artifact_hashes'][str(binary)] and sha(peer)==state['artifact_hashes'][str(peer)], label+' binary changed during run')
                            state['cells'].append({'name': label, 'native': native, 'peer': peer_row, 'passed': True})
                        finally:
                            out, err = stop(proc)
                            peer_log = report.parent/(label+'-peer.log')
                            if not peer_log.exists():
                                peer_log.write_text(out+err)
            state['copied_files_after'] = manifest(copied)
            state['source_files_after'] = manifest(shared, state['copied_files_before'])
            require(state['copied_files_before']==state['copied_files_after']==state['source_files_after'], 'Closure changed during execution')
        state['fixture_sources_after'] = manifest(fixtures, artifacts)
        require(state['fixture_sources_before']==state['fixture_sources_after'], 'Fixture source changed during execution')
        state['standard_sources_after'] = manifest(core, stdnames)
        require(state['standard_sources_before']==state['standard_sources_after'], 'Core sources changed during execution')
        require(state['runner_sha256']==sha(__file__), 'Gate changed during execution')
        require(state['compiler']['sha256']==sha(compiler) and state['go']['sha256']==sha(go) and state['closure_helper_sha256']==sha(helper), 'Toolchain/helper changed during execution')
        state['artifact_hashes_after'] = {name: sha(name) for name in state['artifact_hashes']}
        require(state['artifact_hashes']==state['artifact_hashes_after'], 'Executable artifact changed during execution')
        matrix = []
        for transport in ('tcp','tls'):
            modes = ['framing','framing-fragmented','host-alias','ports','clients','idle','maxage','stale','partial','separate','peer-close']
            if transport=='tls':
                modes += ['scheme','trust','alpn','keyupdate','keyupdate-inline','wrong-host']
            matrix.extend((transport,mode) for mode in modes if a.cases is None or mode in a.cases)
        expected = {san+'-'+transport+'-'+mode for san in a.sanitizers for transport,mode in matrix}
        require(len(state['cells'])==len(expected) and {cell['name'] for cell in state['cells']}==expected, 'Missing or duplicate native matrix cells')
        state['expected_native_cells'] = len(expected)
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
