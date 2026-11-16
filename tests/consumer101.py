#!/usr/bin/env python3
"""Build a physical-copy public Client and unchanged facade consumer, then run it."""
from staging import copy_closure, test_run, test_files
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifest(root, names=None):
    root = Path(root)
    names = names if names is not None else sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file())
    result = {}
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Nonphysical source: ' + str(path))
        result[name] = sha(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('odin', 'core-root', 'shared-root', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    compiler, core, shared, report = [p.resolve() for p in (args.odin, args.core_root, args.shared_root, args.report)]
    report.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ODIN_ROOT=str(core))
    env['PATH'] = '/opt/homebrew/opt/llvm@22/bin:' + env.get('PATH', '')
    state = {'passed': False, 'scope': 'Standalone public Client lifecycle and unchanged facade execution; native requests belong to client101', 'checks': [], 'skipped': []}

    def require(condition, message):
        if not condition:
            raise RuntimeError(message)

    def run(label, command):
        command = list(map(str, command))
        start = time.monotonic()
        result = test_run(command, env=env, capture_output=True, text=True, timeout=120)
        log = report.parent / (label + '.log')
        log.write_text(result.stdout + result.stderr)
        state['checks'].append({'label': label, 'command': command, 'returncode': result.returncode, 'log': str(log), 'log_sha256': sha(log), 'seconds': time.monotonic() - start})
        require(result.returncode == 0, 'Failed ' + str(log))
        return result.stdout

    try:
        state['compiler'] = {'path': str(compiler), 'sha256': sha(compiler), 'version': run('compiler-version', [compiler, 'version']).strip()}
        standard = sorted(str(p.relative_to(core)) for tree in ('base', 'core', 'vendor') for p in (core / tree).rglob('*') if p.is_file() and p.suffix in ('.odin', '.c', '.h', '.s', '.S'))
        state['core_sources_before'] = manifest(core, standard)
        fixture = shared / 'surf/tests/testdata/consumer101/main.odin'
        state['consumer_sha256'] = sha(fixture)
        state['runner_sha256'] = sha(__file__)
        helper = compiler.parent / 'ci/webtools_consumer_gate.py'
        state['closure_helper_sha256'] = sha(helper)
        spec = importlib.util.spec_from_file_location('consumer101_closure', helper)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-consumer-') as directory:
            temp = Path(directory)
            copied = temp / 'shared'
            copied.mkdir()
            state['closure'] = copy_closure(gate, 'surf/async', shared, copied)
            state['copied_sources_before'] = manifest(copied)
            state['source_closure_before'] = manifest(shared, state['copied_sources_before'])
            require(state['copied_sources_before'] == state['source_closure_before'], 'Copy mismatch')
            host = temp / 'host'
            host.mkdir()
            shutil.copyfile(fixture, host / 'main.odin')
            state['binaries'] = {}
            for sanitizer in ('address', 'thread'):
                binary = report.parent / ('consumer-' + sanitizer)
                run('build-' + sanitizer, [compiler, 'build', host, '-collection:shared=' + str(copied), '-warnings-as-errors', '-thread-count:1', '-sanitize:' + sanitizer, '-out:' + str(binary)])
                state['binaries'][str(binary)] = sha(binary)
                run('linked-' + sanitizer, ['otool', '-L', binary])
                output = run('run-' + sanitizer, [binary])
                require(output.strip() == 'CONSUMER101 public_client_prestart=true unchanged_facade=true http1=true heap_zero=true', 'Consumer marker missing')
                require(sha(binary) == state['binaries'][str(binary)], 'Binary changed')
            state['copied_sources_after'] = manifest(copied)
            state['source_closure_after'] = manifest(shared, state['copied_sources_before'])
            require(state['copied_sources_before'] == state['copied_sources_after'] == state['source_closure_after'], 'Source changed')
        state['core_sources_after'] = manifest(core, standard)
        require(state['core_sources_before'] == state['core_sources_after'], 'Core changed')
        require(sha(fixture) == state['consumer_sha256'] and sha(__file__) == state['runner_sha256'], 'Fixture changed')
        require(sha(compiler) == state['compiler']['sha256'] and sha(helper) == state['closure_helper_sha256'], 'Toolchain changed')
        state['passed'] = True
    except Exception as error:
        state['error'] = str(error)
    finally:
        report.write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps({'passed': state['passed'], 'report': str(report), 'error': state.get('error')}))
    return 0 if state['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
