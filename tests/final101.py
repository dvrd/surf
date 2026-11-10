#!/usr/bin/env python3
"""Run and validate the complete current-source OKAMI-101 acceptance matrix."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


class ValidationError(RuntimeError):
    pass


SANITIZERS = ('address', 'thread')
ACTOR_MODES = ('healthy', 'stale', 'partial', 'close', 'setup-deadline', 'body-deadline',
               'cancel-read', 'cancel-mailbox', 'uncertain', 'one-worker', 'lifetime', 'reuse-waiter')
REDIRECT_MODES = tuple(m+str(s) for m in ('get', 'head', 'post') for s in (301, 302, 303, 307, 308)) + (
    'disabled', 'relative', 'cross-public', 'cross-auth', 'cross-cookie', 'cross-custom',
    'loop', 'hopcap', 'bodycap', 'cutoff', 'dns32', 'cancel', 'close', 'handoff-cancel', 'handoff-close')
POOL_MODES = ('framing', 'framing-fragmented', 'host-alias', 'ports', 'clients', 'idle',
              'maxage', 'stale', 'partial', 'separate', 'peer-close')
CANCEL_CASES = tuple(phase+'-'+transport+'-'+action
    for phase in ('dns', 'tls', 'write', 'header', 'body', 'redirect', 'queued')
    for transport in (('tls',) if phase == 'tls' else ('tcp', 'tls'))
    for action in (('cancel', 'total', 'lifetime', 'close', 'shutdown') +
                   (('setup',) if phase in ('dns', 'tls') else ()))) + tuple(
    'rawconnect-'+transport+'-'+action for transport in ('tcp', 'tls')
    for action in ('release_success', 'owner_cancel', 'close_connect', 'runtime_shutdown', 'later_finish', 'earlier_finish'))
SPECS = {
    'foundations': {'runner': 'redirect_foundations101.py', 'native_count': 0, 'units': 18},
    'actor': {'runner': 'session_actor101.py', 'native_count': 48,
              'cases': tuple(t+'-'+m for t in ('tcp', 'tls') for m in ACTOR_MODES)},
    'client': {'runner': 'client101.py', 'native_count': 12, 'units': 6,
               'cases': tuple(t+'-'+m for t in ('tcp', 'tls') for m in ('healthy', 'fragmented', 'progress'))},
    'consumer': {'runner': 'consumer101.py', 'native_count': 0, 'executions': 2},
    'redirect': {'runner': 'redirect101.py', 'native_count': 122, 'units': 2,
                 'cases': tuple(t+'-'+m for t in ('tcp', 'tls') for m in REDIRECT_MODES) + ('tls-downgrade',)},
    'pool': {'runner': 'pool101.py', 'native_count': 56,
             'cases': tuple(t+'-'+m for t in ('tcp', 'tls') for m in POOL_MODES) + tuple(
                 'tls-'+m for m in ('scheme', 'trust', 'alpn', 'keyupdate', 'keyupdate-inline', 'wrong-host'))},
    'cancel': {'runner': 'cancel101.py', 'native_count': 160, 'cases': CANCEL_CASES},
    'concurrency': {'runner': 'concurrency101.py', 'native_count': 8, 'units': 2,
                    'cases': tuple(t+'-'+m for t in ('tcp', 'tls') for m in ('success', 'shutdown'))},
    'failure': {'runner': 'failure101.py', 'native_count': 116, 'units': 3,
                'cases': ('p0-m0',) + tuple('p%d-m%d' % (p, m) for p in range(1, 10) for m in range(1, 7)) +
                         tuple('p4-m%d' % m for m in (7, 8, 9))},
}


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def sha(path):
    require(isinstance(path, (str, os.PathLike)), 'Malformed evidence path')
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as error:
        raise ValidationError('Missing/unreadable evidence: '+str(path)) from error


def physical(path):
    require(isinstance(path, (str, os.PathLike)), 'Malformed physical evidence path')
    p = Path(path)
    require(p.is_file() and not p.is_symlink(), 'Nonphysical file: '+str(p))
    return p


def hash_map(value, label):
    require(isinstance(value, dict) and bool(value), 'Missing '+label)
    require(all(isinstance(k, str) and isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v)
                for k, v in value.items()), 'Malformed '+label)
    return value


def file_map(root, mapping, label):
    root = Path(root).resolve()
    mapping = hash_map(mapping, label)
    for name, expected in mapping.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Escaping '+label+': '+name)
        p = root/relative
        require(p.resolve().is_relative_to(root), 'Escaping '+label+': '+name)
        require(sha(physical(p)) == expected, 'Stale '+label+': '+name)
    return mapping


def paired_map(data, before, after, root, label):
    a = hash_map(data.get(before), before)
    b = hash_map(data.get(after), after)
    require(a == b, 'Changed '+label)
    file_map(root, a, label)
    return a


def source_keys(data):
    for before in ('source_closure_before', 'source_files_before', 'source_sources_before'):
        if before in data:
            return before, before.replace('_before', '_after')
    raise ValidationError('Missing live source closure')


def core_keys(data):
    return ('standard_sources_before', 'standard_sources_after') if 'standard_sources_before' in data else ('core_sources_before', 'core_sources_after')


def all_core_names(core):
    return {str(p.relative_to(core)) for tree in ('base', 'core', 'vendor')
            for p in (core/tree).rglob('*') if p.is_file() and p.suffix in ('.odin', '.c', '.h', '.s', '.S')}


def command_name(row):
    return row.get('name', row.get('label'))


def _validate_receipt(name, data, shared_root: Path, core_root: Path) -> dict:
    """Validate one real receipt and its current physical sources/tools/artifacts.

    This deliberately reads local files. Before/after equality alone cannot turn
    a stale or self-consistently edited source/artifact map into valid evidence.
    """
    require(name in SPECS, 'Unknown required runner: '+str(name))
    spec = SPECS[name]
    require(isinstance(data, dict) and data.get('passed') is True, name+': failed receipt')
    require(not data.get('skipped') and not data.get('partial'), name+': partial/skipped evidence')
    if 'selected_sanitizers' in data:
        require(isinstance(data['selected_sanitizers'], list) and len(data['selected_sanitizers']) == 2 and
                set(data['selected_sanitizers']) == set(SANITIZERS), name+': paired sanitizers required')
    if 'complete_matrix' in data:
        require(data['complete_matrix'] is True and data.get('selected_matrix_passed') is True, name+': incomplete matrix')
    if data.get('selected_cases') is not None:
        selected = data['selected_cases']
        require(isinstance(selected, list) and all(isinstance(v, str) for v in selected) and len(selected) == len(set(selected)) and
                set(selected) == set(spec.get('cases', ())), name+': partial case selection')

    shared, core = Path(shared_root).resolve(), Path(core_root).resolve()
    source_before, source_after = source_keys(data)
    sources = paired_map(data, source_before, source_after, shared, name+' live sources')
    production = {str(p.relative_to(shared)) for p in (shared/'surf/async').rglob('*.odin') if not p.name.endswith('_test.odin')}
    require(production <= set(sources), name+': incomplete production source projection')
    copied_before = 'copied_files_before' if 'copied_files_before' in data else 'copied_sources_before'
    copied_after = copied_before.replace('_before', '_after')
    copied = hash_map(data.get(copied_before), copied_before)
    require(copied == data.get(copied_after), name+': copied sources changed')
    require(copied == sources, name+': physical-copy/live projection mismatch')
    modules = data.get('closure', data.get('closures'))
    if name in ('client', 'redirect', 'pool', 'cancel'):
        require(isinstance(modules, dict) and set(modules) == {'surf/async', 'async/connection'}, name+': missing import roots')
        require(modules['async/connection'] == ['async', 'async/connection'], name+': wrong transport closure')
        modules = modules['surf/async']
    require(isinstance(modules, list) and bool(modules) and all(isinstance(v, str) for v in modules) and len(modules) == len(set(modules)), name+': missing/duplicate import closure')
    require({'surf', 'surf/async', 'surf/async/exchange', 'http/v1', 'async/connection'} <= set(modules), name+': incomplete native import closure')
    for module in modules:
        require(not Path(module).is_absolute() and '..' not in Path(module).parts, name+': escaping import module')
        required = {str(p.relative_to(shared)) for p in (shared/module).glob('*.odin') if p.is_file()}
        require(bool(required) and required <= set(sources), name+': incomplete current imported package '+module)
    if 'source_package_inventory_before' in data:
        inventory = {module: sorted(p.name for p in (shared/module).glob('*.odin') if p.is_file()) for module in modules}
        require(data['source_package_inventory_before'] == data.get('source_package_inventory_after') == inventory,
                name+': stale/incomplete package inventory')
    require(not any(m == 'saba' or m.startswith('saba/') for m in modules) and
            not any(p.startswith('saba/') for p in sources), name+': Saba dependency in native closure')
    cb, ca = core_keys(data)
    core_map = paired_map(data, cb, ca, core, name+' standard sources')
    require(set(core_map) == all_core_names(core), name+': incomplete standard source projection')

    fixture_key = next((k for k in ('fixture_sources_before', 'fixtures_before') if k in data), None)
    if fixture_key:
        fixture_root = shared/'surf/tests' if name == 'pool' else shared/'surf'
        fixtures = paired_map(data, fixture_key, fixture_key.replace('_before', '_after'), fixture_root, name+' fixtures')
        stem = Path(spec['runner']).stem
        prefix = '' if name == 'pool' else 'tests/'
        mandatory = {prefix+spec['runner'], prefix+'testdata/'+stem+'/main.odin', prefix+'testdata/'+stem+'/peer.go'}
        if name == 'cancel':
            mandatory.add('tests/testdata/cancel101/cases.json')
        require(mandatory <= set(fixtures), name+': incomplete fixture projection')
    if 'owned_sources_before' in data:
        paired_map(data, 'owned_sources_before', 'owned_sources_after', shared/'surf', name+' owned sources')
    runner = shared/'surf/tests'/spec['runner']
    if 'runner_sha256' in data:
        require(data['runner_sha256'] == sha(physical(runner)), name+': stale runner')
    else:
        require(fixture_key and data[fixture_key].get('tests/'+spec['runner']) == sha(physical(runner)), name+': runner not bound')
    compiler = data.get('compiler')
    require(isinstance(compiler, dict) and isinstance(compiler.get('path'), str), name+': missing compiler identity')
    require(sha(compiler['path']) == compiler.get('sha256'), name+': compiler changed')
    for key in ('root', 'core_root'):
        if key in compiler:
            require(Path(compiler[key]).resolve() == core, name+': wrong compiler core root')
    helper = Path(compiler['path']).resolve().parent/'ci/webtools_consumer_gate.py'
    helper_hash = data.get('closure_helper_sha256', data.get('helper_sha256'))
    require(helper_hash == sha(physical(helper)), name+': stale closure helper')
    for tool in ('go', 'clang'):
        if tool in data:
            require(isinstance(data[tool], dict) and isinstance(data[tool].get('path'), str) and sha(data[tool]['path']) == data[tool].get('sha256'), name+': stale '+tool)

    commands = data.get('commands', data.get('checks'))
    require(isinstance(commands, list) and bool(commands), name+': missing executed commands')
    command_map = {}
    for row in commands:
        require(isinstance(row, dict), name+': malformed command')
        label = command_name(row)
        require(isinstance(label, str) and label and label not in command_map, name+': missing/duplicate command label')
        require(type(row.get('returncode')) is int and row['returncode'] == 0, name+': failed command '+label)
        require(isinstance(row.get('command'), list) and bool(row['command']) and all(isinstance(x, str) for x in row['command']), name+': malformed command '+label)
        require(sha(physical(row.get('log', ''))) == row.get('log_sha256'), name+': stale command log '+label)
        text = Path(row['log']).read_text()
        require('+++ leak' not in text and '+++ bad free' not in text and 'WARNING: ThreadSanitizer' not in text and
                'ERROR: AddressSanitizer' not in text, name+': memory/sanitizer failure '+label)
        if 'stdout' in row and 'stderr' in row:
            require(row['stdout']+row['stderr'] == text, name+': command/log content mismatch '+label)
        command_map[label] = row
    if 'log_hashes' in data:
        for path, digest in hash_map(data['log_hashes'], 'log hashes').items():
            require(sha(physical(path)) == digest, name+': stale recorded log')

    artifact_key = next((k for k in ('artifact_hashes', 'binary_hashes', 'binaries_before', 'binaries') if k in data), None)
    require(artifact_key is not None, name+': missing binaries')
    artifacts = dict(hash_map(data[artifact_key], 'artifacts'))
    paired_artifact_key = {'artifact_hashes': 'artifact_hashes_after', 'binaries_before': 'binaries_after'}.get(artifact_key)
    if paired_artifact_key:
        require(artifacts == data.get(paired_artifact_key), name+': binary before/after mismatch')
    if name == 'actor':
        peer_command = command_map.get('peer-build', {}).get('command', [])
        require('-o' in peer_command and peer_command.index('-o')+1 < len(peer_command), name+': peer binary unbound')
        artifacts[peer_command[peer_command.index('-o')+1]] = data.get('peer_binary_sha256')
    for path, digest in hash_map(artifacts, 'complete artifacts').items():
        require(sha(physical(path)) == digest, name+': stale binary '+path)
    require(all(any(Path(p).name.endswith('-'+san) for p in artifacts) for san in SANITIZERS), name+': missing sanitizer binary')

    expected = {san+'-'+case for san in SANITIZERS for case in spec.get('cases', ())}
    cells = data.get('cells', [])
    require(isinstance(cells, list), name+': missing cells')
    if expected:
        names = [c.get('name') for c in cells if isinstance(c, dict)]
        require(all(isinstance(v, str) for v in names) and len(names) == len(cells) == len(expected) == spec['native_count'] and len(set(names)) == len(names) and
                set(names) == expected, name+': missing/duplicate/unknown matrix cells')
        require(type(data.get('native_execution_count')) is int and data['native_execution_count'] == len(expected), name+': native execution count mismatch')
        if 'expected_native_cells' in data:
            require(data['expected_native_cells'] == len(expected), name+': expected native count mismatch')
        if 'required_matrix' in data:
            require(isinstance(data['required_matrix'], list) and len(data['required_matrix']) == len(expected) and
                    set(data['required_matrix']) == expected, name+': required matrix was truncated/changed')
        for cell in cells:
            label = cell['name']
            require((cell.get('passed') is True if name != 'failure' else cell.get('passed', True) is True) and
                    label in command_map, name+': failed/unexecuted cell '+label)
            require(command_map[label]['command'][0] in artifacts, name+': executed native binary not bound '+label)
            proof = cell.get('proof', {})
            require(isinstance(proof, dict), name+': malformed proof '+label)
            native = cell.get('native', proof.get('summary', {}))
            require(isinstance(native, dict) and bool(native), name+': missing native proof '+label)
            for fact in (('scope_zero',) if name == 'actor' else ('scope_zero', 'heap_zero', 'fd_zero')):
                require(native.get(fact) is True, name+': failed/missing cleanup '+label+'/'+fact)
            if name == 'actor':
                cleanup = proof.get('cleanup', {})
                require(isinstance(cleanup, dict) and cleanup.get('heap_zero') is True and
                        type(cleanup.get('fd_delta')) is int and cleanup['fd_delta'] == 0, 'actor: cleanup failure '+label)
            records = []
            for line in Path(command_map[label]['log']).read_text().splitlines():
                if line.startswith('{'):
                    try:
                        records.append(json.loads(line))
                    except ValueError:
                        pass
            require(native in records, name+': native proof/log mismatch '+label)
            if name == 'failure':
                match = re.fullmatch(r'(address|thread)-p(\d+)-m(\d+)', label)
                point, mode = map(int, match.groups()[1:])
                require(cell.get('point') == native.get('point') == point and cell.get('mode') == native.get('mode') == mode,
                        'failure: point/mode alias '+label)
                require(native.get('header_freed') is True and native.get('hits') == (0 if mode == 0 else 1), 'failure: injection not exercised '+label)
                require(native.get('error') == ('None' if mode == 0 else 'Allocation_Failed' if mode <= 7 else 'IO_Failed'), 'failure: native outcome '+label)
                if mode == 0:
                    require(native.get('calls') == 9 and len(native.get('sizes', [])) == len(native.get('alignments', [])) == 9,
                            'failure: changed allocation census')
            if 'peer_log' in cell:
                require(sha(physical(cell['peer_log'])) == cell.get('peer_log_sha256'), name+': stale peer log '+label)
        for san in SANITIZERS:
            builds = [row for row in commands if row['command'][0] == compiler['path'] and 'build' in row['command'] and
                      '-sanitize:'+san in row['command']]
            require(bool(builds), name+': native sanitizer not built '+san)
        if name == 'cancel':
            for san in SANITIZERS:
                selected = [c for c in cells if c['name'].startswith(san+'-')]
                layers = {layer: sum(c.get('native', {}).get('layer') == layer for c in selected)
                          for layer in ('public_client', 'runtime_connect_slot')}
                require(layers == {'public_client': 68, 'runtime_connect_slot': 12}, 'cancel: required layer counts')
    elif name == 'foundations':
        require(type(data.get('native_execution_count')) is int and data['native_execution_count'] == 0 and
                data.get('expected_aggregate_count') == 18, 'foundations: wrong proof/count')
        streams = data.get('streams')
        require(isinstance(streams, dict) and set(streams) == {'ledger', 'prepare', 'queue'}, 'foundations: missing independent streams')
        requested = []
        for stream, count in (('ledger', 6), ('prepare', 5), ('queue', 7)):
            info = streams[stream]
            require(isinstance(info, dict) and isinstance(info.get('path'), str), 'foundations: malformed stream')
            path = shared/'surf'/info['path']
            actual = re.findall(r'@\(test\)\s*(\w+)\s*::\s*proc\b', path.read_text())
            require(info.get('aggregate_count') == count and len(actual) == count and info.get('test_names') == actual and
                    info.get('source_sha256') == sha(path), 'foundations: stream mismatch '+stream)
            requested.extend(actual)
        require(data.get('requested_test_names') == requested, 'foundations: incomplete test selection')
    elif name == 'consumer':
        require(data.get('consumer_sha256') == sha(physical(shared/'surf/tests/testdata/consumer101/main.odin')), 'consumer: stale fixture')
        for san in SANITIZERS:
            run = command_map.get('run-'+san)
            require(run and run['command'][0] in artifacts, 'consumer: missing real execution '+san)
            require(Path(run['log']).read_text().strip() == 'CONSUMER101 public_client_prestart=true unchanged_facade=true http1=true heap_zero=true', 'consumer: missing execution marker')
    else:
        raise ValidationError(name+': unsupported receipt shape')

    if 'units' in spec:
        for san in SANITIZERS:
            labels = (('focused-'+san,) if name == 'foundations' else ('unit-'+san, 'units-'+san))
            found = [command_map[label] for label in labels if label in command_map]
            require(len(found) == 1, name+': missing/duplicate unit run '+san)
            row = found[0]
            output = Path(row['log']).read_text()
            require(re.findall(r'Finished (\d+) tests? in ', output) == [str(spec['units'])] and
                    'All tests were successful' in output, name+': wrong/nonzero unit aggregate count '+san)
            require('-sanitize:'+san in row['command'] and '-define:ODIN_TEST_THREADS=1' in row['command'] and
                    '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true' in row['command'], name+': weakened unit command '+san)
    return {'name': name, 'passed': True, 'native_execution_count': spec['native_count'],
            'cell_names': sorted(expected), 'sanitizers': list(SANITIZERS), 'source_count': len(sources), 'artifact_count': len(artifacts)}


def validate_receipt(name, data, shared_root: Path, core_root: Path) -> dict:
    try:
        return _validate_receipt(name, data, shared_root, core_root)
    except ValidationError:
        raise
    except (TypeError, KeyError, ValueError, OSError, AttributeError) as error:
        raise ValidationError(str(name)+': malformed/unreadable receipt: '+str(error)) from error


def current_manifest(root, extensions=None):
    root = Path(root)
    result = {}
    for p in sorted(root.rglob('*')):
        if not p.is_file() or '.git' in p.parts or '.cruft' in p.parts or '__pycache__' in p.parts or p.suffix == '.pyc':
            continue
        if extensions is not None and p.suffix not in extensions:
            continue
        result[str(p.relative_to(root))] = sha(physical(p))
    return result


def production_manifest(shared, package):
    root = Path(shared)/package
    require(root.is_dir(), 'Missing explicit compatibility SDK: '+str(root))
    return {str(p.relative_to(root)): sha(physical(p)) for p in sorted(root.rglob('*.odin'))
            if not p.name.endswith('_test.odin') and not any(part in ('tests', 'testdata', '.git', '.cruft')
                                                         for part in p.relative_to(root).parts)}


def validate_service_compatibility(data, shared, core, compiler):
    require(isinstance(data, dict) and data.get('passed') is True and not data.get('skipped_packages'), 'Service compatibility failed/skipped')
    require(Path(data.get('shared_source', '')).resolve() == shared and Path(data.get('stdlib_root', '')).resolve() == core,
            'Service compatibility source/core root mismatch')
    require(Path(data.get('compiler', '')).resolve() == compiler and data.get('compiler_sha256') == sha(compiler), 'Service compatibility compiler mismatch')
    checks = data.get('checks')
    require(isinstance(checks, list) and [row.get('name') for row in checks] == ['empty executable', 'aws', 'google', 'auth'],
            'Missing/duplicate service compatibility consumer')
    for row in checks:
        require(row.get('passed') is True, 'Failed compatibility consumer '+str(row.get('name')))
        for operation in ('build', 'run'):
            result = row.get(operation)
            require(isinstance(result, dict) and type(result.get('returncode')) is int and result['returncode'] == 0,
                    'Compatibility command failed: '+str(row.get('name'))+'/'+operation)
        if row['name'] != 'empty executable':
            require(row.get('source_unchanged') is True and row.get('copy_unchanged') is True and
                    row.get('source_files') == row.get('copied_files'), 'Service source/copy changed')
            records = row.get('source_files')
            require(isinstance(records, dict) and bool(records), 'Missing service source records')
            hashes = {}
            for relative, record in records.items():
                require(isinstance(relative, str) and isinstance(record, dict) and set(record) == {'bytes', 'sha256'} and
                        type(record['bytes']) is int and record['bytes'] >= 0, 'Malformed service source record')
                hashes[relative] = record['sha256']
            file_map(shared, hashes, 'service compatibility '+row['name'])
            for relative, record in records.items():
                require(physical(shared/relative).stat().st_size == record['bytes'], 'Service source byte count changed: '+relative)
    return {'passed': True, 'consumers': ['aws', 'google', 'auth'], 'empty_baseline': True,
            'scope': 'Isolated import/build/link/run compatibility only; no service migration, behavioral or offload implementation claim'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('odin', 'core-root', 'shared-root', 'service-shared-root', 'report'):
        parser.add_argument('--'+key, type=Path, required=True)
    a = parser.parse_args()
    compiler, core, shared, report = [p.resolve() for p in (a.odin, a.core_root, a.shared_root, a.report)]
    service_shared = a.service_shared_root.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    require(not report.exists(), 'Refusing to overwrite an existing final receipt')
    directory = report.parent/'subreports'
    require(not directory.exists(), 'Final subreport directory must be fresh')
    directory.mkdir()
    state = {'passed': False, 'scope': 'Current-source required Webtools101 acceptance; Darwin only',
             'commands': [], 'required_runners': list(SPECS), 'subreports': {}, 'skipped': []}
    env = dict(os.environ, ODIN_ROOT=str(core), GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0')
    env['PATH'] = '/opt/homebrew/opt/llvm@22/bin:'+env.get('PATH', '')
    for key in list(env):
        if key.startswith(('AWS_', 'GOOGLE_', 'GCLOUD_', 'AZURE_')):
            del env[key]

    def run(label, command, timeout=3600):
        command = list(map(str, command))
        started = time.monotonic()
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=timeout)
        log = report.parent/(label+'.log')
        log.write_text(result.stdout+result.stderr)
        state['commands'].append({'name': label, 'command': command, 'returncode': result.returncode,
                                  'log': str(log), 'log_sha256': sha(log), 'seconds': time.monotonic()-started})
        require(result.returncode == 0, label+' failed: '+str(log))
        return result.stdout+result.stderr

    try:
        require(sys.platform == 'darwin', 'This final matrix requires owned Darwin evidence, not a platform skip')
        state['compiler'] = {'path': str(compiler), 'sha256': sha(compiler), 'version': run('compiler-version', [compiler, 'version']).strip()}
        state['shared_before'] = current_manifest(shared/'surf', {'.odin', '.py', '.go', '.json', '.md'})
        state['core_before'] = {p: sha(core/p) for p in sorted(all_core_names(core))}
        state['runner_sha256'] = sha(__file__)
        state['service_compatibility'] = {'shared_root': str(service_shared), 'scope': 'Build/run compatibility only, no service/application migration or offload implementation certification'}
        matching = {}
        for package in ('surf', 'http', 'async'):
            candidate = production_manifest(shared, package)
            canonical = production_manifest(service_shared, package)
            require(bool(candidate) and canonical == candidate, 'Canonical/candidate production SDK mismatch: '+package)
            matching[package] = candidate
        state['service_compatibility']['production_sdk_before'] = matching
        service_status = {}
        for package in ('aws', 'google', 'auth'):
            service_status[package] = {
                'revision': run('service-'+package+'-revision-before', ['git', '-C', service_shared/package, 'rev-parse', 'HEAD']).strip(),
                'status': run('service-'+package+'-status-before', ['git', '-C', service_shared/package, 'status', '--short']),
            }
        state['service_compatibility']['repositories_before'] = service_status
        helper = compiler.parent/'ci/webtools_consumer_gate.py'
        state['service_compatibility']['helper_sha256'] = sha(physical(helper))
        compatibility_report = directory/'service-compatibility/receipt.json'
        compatibility_report.parent.mkdir()
        run('service-compatibility', [sys.executable, helper, '--odin', compiler, '--source-root', core,
            '--shared-root', service_shared, '--packages', 'aws', 'google', 'auth', '--report', compatibility_report])
        compatibility = json.loads(compatibility_report.read_text())
        state['service_compatibility'].update(report=str(compatibility_report), report_sha256=sha(compatibility_report),
            summary=validate_service_compatibility(compatibility, service_shared, core, compiler))
        for name, spec in SPECS.items():
            target = directory/name/'receipt.json'
            target.parent.mkdir()
            command = [sys.executable, shared/'surf/tests'/spec['runner'], '--odin', compiler,
                       '--core-root', core, '--shared-root', shared, '--report', target]
            run('runner-'+name, command)
            require(target.is_file(), name+': runner wrote no receipt')
            data = json.loads(target.read_text())
            summary = validate_receipt(name, data, shared, core)
            state['subreports'][name] = {'path': str(target), 'sha256': sha(target), 'summary': summary}

        # Independent controls exercise the actual freshly generated real schema.
        run('negative-controls', [sys.executable, shared/'surf/tests/test_final101.py', '--runner', Path(__file__).resolve(),
            '--receipt', directory/'concurrency/receipt.json', '--shared-root', shared, '--core-root', core])
        state['whole_packages'] = {}
        for package in ('surf/async', 'surf/async/exchange', 'surf/tests'):
            counts = []
            expected_names = re.findall(r'@\(test\)\s*(\w+)\s*::', '\n'.join(p.read_text() for p in sorted((shared/package).glob('*.odin'))))
            require(bool(expected_names) and len(expected_names) == len(set(expected_names)), 'Whole-package discovered test set invalid: '+package)
            for san in SANITIZERS:
                label = 'whole-'+package.replace('/', '-')+'-'+san
                binary = report.parent/label
                output = run(label, [compiler, 'test', shared/package, '-collection:shared='+str(shared),
                    '-warnings-as-errors', '-thread-count:1', '-sanitize:'+san, '-define:ODIN_TEST_THREADS=1',
                    '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true', '-keep-executable', '-out:'+str(binary)])
                found = re.findall(r'Finished (\d+) tests? in ', output)
                require(found == [str(len(expected_names))] and 'All tests were successful' in output, 'Whole package count mismatch: '+label)
                counts.append(int(found[0]))
            if package == 'surf/tests':
                require(counts == [27, 27], 'Unchanged facade27 tests required')
            state['whole_packages'][package] = {'counts': counts, 'test_names': expected_names}

        state['native_link_audits'] = {}
        for name in ('actor', 'client', 'redirect', 'pool', 'cancel', 'concurrency', 'failure'):
            data = json.loads((directory/name/'receipt.json').read_text())
            artifacts = data.get('artifact_hashes', data.get('binary_hashes', {}))
            for san in SANITIZERS:
                binary = next((Path(p) for p in artifacts if Path(p).name == 'native-'+san), None)
                require(binary is not None, name+': native binary unavailable for link audit')
                linkage = run('audit-'+name+'-'+san+'-linked', ['otool', '-L', binary])
                undefined = run('audit-'+name+'-'+san+'-undefined', ['nm', '-u', binary])
                require(not re.search(r'libcurl|nghttp2|saba', linkage, re.I), name+': native provider/adapter linked')
                require(not re.search(r'\b_?curl_easy_perform\b|\b_?curl_multi_\w+|\b_?nghttp2_\w+', undefined), name+': native external HTTP call')
                state['native_link_audits'][name+'-'+san] = {'binary': str(binary), 'sha256': sha(binary), 'no_easy_perform': True, 'no_saba': True}

        state['shared_after'] = current_manifest(shared/'surf', {'.odin', '.py', '.go', '.json', '.md'})
        state['core_after'] = {p: sha(core/p) for p in sorted(all_core_names(core))}
        require(state['shared_before'] == state['shared_after'] and state['core_before'] == state['core_after'], 'Final source changed during execution')
        require(state['runner_sha256'] == sha(__file__) and state['compiler']['sha256'] == sha(compiler), 'Final tool changed')
        require(sha(compatibility_report) == state['service_compatibility']['report_sha256'] and sha(helper) == state['service_compatibility']['helper_sha256'],
                'Service compatibility report/helper changed')
        validate_service_compatibility(json.loads(compatibility_report.read_text()), service_shared, core, compiler)
        for package, expected in matching.items():
            require(production_manifest(shared, package) == production_manifest(service_shared, package) == expected,
                    'Compatibility SDK changed: '+package)
        for package, expected in service_status.items():
            revision = run('service-'+package+'-revision-after', ['git', '-C', service_shared/package, 'rev-parse', 'HEAD']).strip()
            status = run('service-'+package+'-status-after', ['git', '-C', service_shared/package, 'status', '--short'])
            require(expected == {'revision': revision, 'status': status}, 'Service repository state changed: '+package)
        state['service_compatibility']['production_sdk_after'] = matching
        state['service_compatibility']['repositories_after'] = service_status
        require(set(state['subreports']) == set(SPECS), 'Missing required subreport')
        for name, info in state['subreports'].items():
            require(sha(info['path']) == info['sha256'], 'Subreport changed: '+name)
            validate_receipt(name, json.loads(Path(info['path']).read_text()), shared, core)
        state.update(passed=True, native_matrix_cells=522, standalone_consumer_executions=2,
                     foundation_aggregates_per_sanitizer=18, cancellation_layers_per_sanitizer={'public_client': 68, 'runtime_connect_slot': 12})
    except Exception as error:
        state['error'] = str(error)
    finally:
        report.write_text(json.dumps(state, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'passed': state['passed'], 'report': str(report), 'error': state.get('error')}))
    return 0 if state['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
