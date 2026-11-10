#!/usr/bin/env python3
"""Strict paired public held-phase cancellation and one-worker progress gate."""
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


def required_names():
    names={phase+'-'+transport+'-'+action
           for phase in ('dns','tls','write','header','body','redirect','queued')
           for transport in (('tls',) if phase=='tls' else ('tcp','tls'))
           for action in (('cancel','total','lifetime','close','shutdown')+(('setup',) if phase in ('dns','tls') else ()))}
    names.update('rawconnect-'+transport+'-'+mode for transport in ('tcp','tls')
                 for mode in ('release_success','owner_cancel','close_connect','runtime_shutdown','later_finish','earlier_finish'))
    return names


def verify_raw(case,native,peer,label):
    encrypted=case['transport']=='tls';mode=case['action']
    require(native['layer']=='runtime_connect_slot' and native['mode']==mode and native['cheap_tls']==encrypted,label+' layer/mode mismatch')
    require(native['error']==case['expected_runtime_error'],label+' Runtime error mismatch')
    require(native['workers']==native['client_completions']==native['owner_done_calls']==1,label+' worker/terminal count')
    for fact in ('cheap_before_release','peer_accepted','connecting_slot_held','external_socket_outside_client_cap','scope_zero','heap_zero','fd_zero'):
        require(native[fact] is True,label+' missing '+fact)
    require(native['original_cutoff_retained']==native['later_budget_rejected']==(mode=='later_finish'),label+' original/later budget proof mismatch')
    require(native['earlier_budget_selected']==(mode=='earlier_finish'),label+' shorter budget proof mismatch')
    require(peer['phase']=='rawconnect' and peer['tls']==encrypted and peer['cheap_before_release'] is True and peer['dns_ids']==[],label+' raw peer scope mismatch')
    raw=[e for e in peer['events'] if e['connection_id']==1];cheap=[e for e in peer['events'] if e['connection_id']==100]
    require(len(raw)==len(cheap)==1 and len(peer['events'])==2,label+' raw/cheap event count')
    require(raw[0]['request_bytes']==raw[0]['response_bytes']==raw[0]['negotiated_tls']==0 and raw[0]['alpn']=='',label+' raw socket carried unexpected protocol bytes')
    require(cheap[0]['method']=='GET' and cheap[0]['path']=='/cheap' and cheap[0]['response_bytes']>0,label+' cheap request oracle')
    require(cheap[0]['alpn']==('http/1.1' if encrypted else '') and cheap[0]['negotiated_tls']==(0x304 if encrypted else 0),label+' cheap actual TLS/ALPN')


def verify_peer(case,native,peer,label):
    if case['layer']=='runtime_connect_slot':
        verify_raw(case,native,peer,label);return
    require(case['layer']==native['layer']=='public_client',label+' public Client layer mismatch')
    phase,encrypted=case['phase'],case['transport']=='tls'
    require(peer['phase']==phase and peer['tls']==encrypted,label+' peer case mismatch')
    require(native['expected_stage']==native['observed_stage']==case['expected_stage'],label+' public stage mismatch')
    require(native['phase']==case['expected_terminal_phase'],label+' documented terminal policy mismatch')
    require(native['completed']==(3 if phase=='queued' else 2),label+' terminal count')
    require(native['workers']==native['work_per_resume']==1,label+' worker/work quantum')
    for fact in ('cheap_before_release','terminal_once','heap_zero','scope_zero','fd_zero'):
        require(native[fact] is True,label+' native missing '+fact)
    require(peer['cheap_before_release'] is True,label+' peer did not observe cheap progress before release')
    events=peer['events'];cheap=[e for e in events if e['connection_id']==100];held=[e for e in events if e['connection_id']!=100]
    require(len(cheap)==1 and cheap[0]['path']=='/cheap' and cheap[0]['response_bytes']>0,label+' cheap request oracle')
    require(len(held)==(0 if phase=='dns' else 2 if phase=='redirect' else 1),label+' held wire count')
    if phase=='dns':
        require(len(peer['dns_ids'])>0 and native['dns_ids_remaining']<64,label+' positive DNS draw not exercised')
        require(set(peer['dns_names'])=={'held.cancel.test'} and all(t in (1,28) for t in peer['dns_types']) and all(n>=17 for n in peer['dns_bytes']),label+' literal DNS question oracle')
    else:require(peer['dns_ids']==[],label+' unexpected DNS traffic')
    for e in held:
        if phase=='tls':require(e['clienthello_bytes']>5 and e['request_bytes']==0,label+' missing held ClientHello');continue
        require(e['request_bytes']>0 and e['method']==('POST' if phase=='write' else 'GET'),label+' request wire method/bytes')
        require(e['alpn']==('http/1.1' if encrypted else '') and e['negotiated_tls']==(0x304 if encrypted else 0),label+' actual TLS/ALPN')
    if phase=='write':require(held[0]['content_length']==18<<20 and held[0]['request_bytes']<held[0]['content_length'] and held[0]['response_bytes']==0,label+' pending write not held')
    if phase in ('body','queued'):require(held[0]['response_bytes']>0,label+' partial response body absent')
    if phase=='redirect':require([e['path'] for e in held]==['/held','/redirected'] and native['status']==307,label+' redirect cutoff context')
    if phase=='body':require(native['status']==200 and native['write_effect']=='Response_Received',label+' partial body classification')
    if phase in ('write','header','redirect'):require(native['write_effect']=='Unknown',label+' observed application write effect lost')
    if phase in ('dns','tls','queued'):require(native['write_effect']=='Not_Sent',label+' pre-write effect classification')
    if case['action'] in ('total','setup','lifetime') and not (phase=='queued' and case['action']=='lifetime'):
        require(native['error']=='Deadline_Failed' and native['phase']=='Deadline' and native['elapsed_ms']<2000,label+' original deadline classification')
    else:require(native['phase']=='Cancellation',label+' cancellation classification')


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

    report.parent.mkdir(parents=True, exist_ok=True)
    here = shared / 'surf'
    state = {'passed': False, 'scope': '68 public Client held-phase cases plus12 explicitly layered public Runtime Connecting-slot boundaries; one-worker cheap TCP/TLS progress; Darwin stalled SYN unverified; no private completion injection',
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
            done = subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout)
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
        require((shared/'async/stream_probe.odin').is_file(), 'Explicit shared lacks public nonconsuming stream probe')
        go = Path(shutil.which('go', path=env['PATH'])).resolve()
        state['go'] = {'path': str(go), 'sha256': sha(go), 'version': run('go-version', [go, 'version']).strip()}
        state['compiler'] = {'path': str(compiler), 'sha256': sha(compiler), 'version': run('compiler-version', [compiler, 'version']).strip(), 'root': str(core)}
        stdnames = sorted(str(x.relative_to(core)) for folder in ('base', 'core', 'vendor') for x in (core/folder).rglob('*') if x.is_file() and x.suffix in ('.odin', '.h', '.c', '.s', '.S'))
        state['standard_sources_before'] = manifest(core, stdnames)
        state['runner_sha256'] = sha(__file__)
        artifacts = ['tests/cancel101.py', 'tests/testdata/cancel101/main.odin', 'tests/testdata/cancel101/peer.go', 'tests/testdata/cancel101/cases.json']
        state['fixture_sources_before'] = manifest(here, artifacts)
        cases_document=json.loads((here/'tests/testdata/cancel101/cases.json').read_text())
        cases=cases_document['cases']
        require(cases_document['expected_cases']==len(cases)==80 and len({c['name'] for c in cases})==80 and {c['name'] for c in cases}==required_names(), 'Required literal held-phase case matrix changed')
        require(all(c['name']==c['phase']+'-'+c['transport']+'-'+c['action'] and c['class']==('held_phase' if c['layer']=='public_client' else 'accepted_connecting_boundary') for c in cases), 'Case alias/class mismatch')
        require(cases_document['workers']==cases_document['work_per_resume']==1 and cases_document['sanitizers']==['address','thread'], 'Required execution policy changed')
        require(cases_document['required_layers']=={'public_client':68,'runtime_connect_slot':12} and {layer:sum(c['layer']==layer for c in cases) for layer in cases_document['required_layers']}==cases_document['required_layers'], 'Required layers changed')
        state['required_cases']=cases
        state['platform_scope']=cases_document['platform_scope']
        state['lifetime_policy']=cases_document['lifetime_policy']
        state['timeout_policy']=cases_document['timeout_policy']
        helper = compiler.parent/'ci/webtools_consumer_gate.py'
        state['closure_helper_sha256'] = sha(helper)
        spec = importlib.util.spec_from_file_location('exchange_closure', helper)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-cancel30-') as tmp:
            temp = Path(tmp)
            copied = temp/'shared'
            copied.mkdir()
            state['closures'] = {name: gate.copy_closure(name, shared, copied) for name in ('surf/async', 'async/connection')}
            state['copied_files_before'] = manifest(copied)
            state['source_files_before'] = manifest(shared, state['copied_files_before'])
            package_dirs=sorted({str(Path(n).parent) for n in state['copied_files_before'] if n.endswith('.odin')})
            def package_inventory():
                return {name:sorted(p.name for p in (shared/name).iterdir() if p.is_file() and p.suffix=='.odin') for name in package_dirs}
            state['source_package_inventory_before']=package_inventory()
            require(state['copied_files_before'] == state['source_files_before'], 'Physical closure hash mismatch')
            host = temp/'host'
            host.mkdir()
            shutil.copyfile(here/'tests/testdata/cancel101/main.odin', host/'main.odin')
            state['host_sha256'] = sha(host/'main.odin')
            peer = report.parent/'peer'
            shutil.copyfile(here/'tests/testdata/cancel101/peer.go', temp/'peer.go')
            run('peer-build', [go, 'build', '-o', peer, temp/'peer.go'])
            state['peer_sha256'] = sha(here/'tests/testdata/cancel101/peer.go')
            state['artifact_hashes'][str(peer)] = sha(peer)
            require(state['fixture_sources_before']['tests/testdata/cancel101/main.odin']==sha(host/'main.odin'), 'Host source copy mismatch')
            require(state['peer_sha256']==sha(temp/'peer.go'), 'Peer physical source copy mismatch')
            require(state['fixture_sources_before']['tests/testdata/cancel101/peer.go']==state['peer_sha256'], 'Peer source changed during build')
            for sanitizer in a.sanitizers:
                binary = report.parent/('native-'+sanitizer)
                flags = ['-collection:shared='+str(copied), '-warnings-as-errors', '-thread-count:1', '-sanitize:'+sanitizer]
                run('host-build-'+sanitizer, [compiler, 'build', host, *flags, '-out:'+str(binary)])
                state['artifact_hashes'][str(binary)] = sha(binary)
                for case in cases:
                    encrypted=case['transport']=='tls'
                    phase,action=case['phase'],case['action']
                    label=sanitizer+'-'+case['name']
                    directory=temp/label
                    command=[str(peer),'-phase',phase,'-dir',str(directory)]+(['-tls'] if encrypted else [])
                    proc=subprocess.Popen(command,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                    try:
                        require(select.select([proc.stdout],[],[],10)[0],label+' readiness timeout')
                        endpoint=proc.stdout.readline().strip()
                        require(endpoint.startswith('127.0.0.1:'),label+' invalid endpoint '+endpoint)
                        output=run(label,[binary,endpoint,phase,case['transport'],action,directory],timeout=25)
                        state['native_execution_count']+=1
                        rows=[json.loads(x) for x in output.splitlines() if x.startswith('{')]
                        require(len(rows)==1,label+' native evidence missing')
                        out,err=proc.communicate(timeout=5)
                        require(proc.returncode==0,label+' peer failed '+out+err)
                        peer_rows=[json.loads(x) for x in out.splitlines() if x.startswith('{')]
                        require(len(peer_rows)==1,label+' peer receipt missing')
                        verify_peer(case,rows[0],peer_rows[0],label)
                        (report.parent/(label+'-peer.log')).write_text(out+err)
                        require(sha(binary)==state['artifact_hashes'][str(binary)] and sha(peer)==state['artifact_hashes'][str(peer)],label+' executable changed')
                        state['cells'].append({'name':label,'native':rows[0],'peer':peer_rows[0],'passed':True})
                    finally:
                        out,err=stop(proc)
                        peer_log=report.parent/(label+'-peer.log')
                        if not peer_log.exists():peer_log.write_text(out+err)
            state['copied_files_after'] = manifest(copied)
            state['source_files_after'] = manifest(shared, state['copied_files_before'])
            state['source_package_inventory_after']=package_inventory()
            require(state['source_package_inventory_before']==state['source_package_inventory_after'], 'Source package Odin file inventory changed during execution')
            require(state['copied_files_before']==state['copied_files_after']==state['source_files_after'], 'Closure changed during execution')
        state['fixture_sources_after'] = manifest(here, artifacts)
        require(state['fixture_sources_before']==state['fixture_sources_after'], 'Fixture source changed during execution')
        state['standard_sources_after'] = manifest(core, stdnames)
        require(state['standard_sources_before']==state['standard_sources_after'], 'Core sources changed during execution')
        require(state['runner_sha256']==sha(__file__), 'Gate changed during execution')
        require(state['compiler']['sha256']==sha(compiler) and state['go']['sha256']==sha(go) and state['closure_helper_sha256']==sha(helper), 'Toolchain/helper changed during execution')
        state['artifact_hashes_after'] = {name: sha(name) for name in state['artifact_hashes']}
        require(state['artifact_hashes']==state['artifact_hashes_after'], 'Executable artifact changed during execution')
        expected={san+'-'+case['name'] for san in a.sanitizers for case in cases}
        require(len(expected)==160, 'Required paired matrix changed')
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
