#!/usr/bin/env python3
"""Physical-copy pure Surf101 kernel consumer, paired units and facade regressions.

No async Client actor, socket, TLS or persistent HTTP transport is executed here.
"""
from staging import copy_closure, test_run, test_files
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifest(root, paths=None):
    root = Path(root)
    paths = paths if paths is not None else sorted(
        str(p.relative_to(root)) for p in root.rglob('*')
        if p.is_file() and '__pycache__' not in p.parts)
    result = {}
    for name in paths:
        path = root / name
        assert path.is_file() and not path.is_symlink(), ('nonregular source', str(path))
        result[name] = sha(path)
    return result


def standard_sources(root):
    return {str(p.relative_to(root)): sha(p) for tree in ('base', 'core', 'vendor')
            for p in sorted((root / tree).rglob('*'))
            if p.is_file() and p.suffix in {'.odin', '.c', '.h', '.s', '.S'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    compiler, report = args.odin.resolve(), args.report.resolve()
    stdlib = compiler.parent
    source = Path(__file__).resolve().parents[2]
    helper = stdlib / 'ci/webtools_consumer_gate.py'
    artifacts = report.parent / (report.stem + '-artifacts')
    artifacts.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ODIN_ROOT=str(stdlib))
    env['PATH'] = '/opt/homebrew/opt/llvm@22/bin' + os.pathsep + env.get('PATH', '')
    for key in list(env):
        if key.startswith(('AWS_', 'GOOGLE_', 'GCLOUD_', 'AZURE_')):
            del env[key]
    state = dict(passed=False, scope='Pure kernel and memory codec only; no async Client actor, socket/TLS authentication, persistent transport or full101 proof',
                 platform=platform.platform(), source_root=str(source), gate_sha256=sha(__file__),
                 sanitizers=['address', 'thread'], skipped=[], checks=[])

    def run(label, command, tests=None):
        started = time.monotonic()
        cell = dict(name=label, command=list(map(str, command)))
        state['checks'].append(cell)
        try:
            result = test_run(command, env=env, capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr
            cell['returncode'] = result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            output = str(error)
            cell.update(returncode=None, error=type(error).__name__)
        log = artifacts / (label + '.log')
        log.write_text(output)
        cell.update(seconds=time.monotonic() - started, log=str(log), log_sha256=sha(log))
        assert cell['returncode'] == 0, ('failed command', label, str(log))
        assert '+++ leak' not in output and '+++ bad free' not in output
        if tests is not None:
            actual = re.findall(r'Finished (\d+) tests? in ', output)
            assert actual == [str(tests)] and 'All tests were successful.' in output, (label, actual)
            cell['actual_tests'] = tests
        return cell, output

    try:
        spec = importlib.util.spec_from_file_location('webtools_kernel_closure', helper)
        closure_helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(closure_helper)
        state['closure_helper'] = dict(path=str(helper), sha256=sha(helper))
        state['compiler'] = dict(path=str(compiler), sha256=sha(compiler),
                                 version=subprocess.check_output([compiler, 'version'], env=env, text=True).strip(),
                                 clang=subprocess.check_output(['clang', '--version'], env=env, text=True),
                                 standard_sources=standard_sources(stdlib))
        link_tool = ['otool', '-L'] if platform.system() == 'Darwin' else ['ldd']
        state['compiler']['linked_libraries'] = subprocess.check_output(link_tool + [str(compiler)], env=env, text=True)
        with tempfile.TemporaryDirectory(prefix='surf101-kernel-copy-') as temp:
            copied = Path(temp) / 'shared'
            packages = set()
            for package in ('surf/tests/testdata/kernel101', 'surf/async', 'surf/tests'):
                packages.update(copy_closure(closure_helper, package, source, copied))
            assert not any(p.is_symlink() for p in copied.rglob('*'))
            state['dependency_packages'] = sorted(packages)
            state['copied_root'] = str(copied)
            state['source_before'] = manifest(source, manifest(copied))
            state['copy_before'] = manifest(copied)
            assert state['source_before'] == state['copy_before']
            # Prevent accepting a reduced or zero-test closure.
            expected = {'surf/async': 116, 'surf/tests': 29}
            for package, count in expected.items():
                declared = sum(len(re.findall(r'^\s*@\(test\)', p.read_text(), re.M))
                               for p in test_files(copied / package))
                assert declared == count, (package, declared)
            for sanitizer in state['sanitizers']:
                common = ['-collection:shared=' + str(copied), '-warnings-as-errors', '-sanitize:' + sanitizer]
                for package, count in expected.items():
                    label = sanitizer + '-' + package.replace('/', '-')
                    binary = artifacts / label
                    cell, _ = run(label, [compiler, 'test', copied / package, *common, '-thread-count:1',
                                          '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true',
                                          '-keep-executable', '-out:' + str(binary)], tests=count)
                    cell['binary_sha256'] = sha(binary)
                binary = artifacts / ('consumer-' + sanitizer)
                cell, _ = run(sanitizer + '-consumer-build', [compiler, 'build',
                              copied / 'surf/tests/testdata/kernel101', *common, '-out:' + str(binary)])
                cell.update(binary=str(binary), binary_sha256=sha(binary),
                            linked_libraries=subprocess.check_output(link_tool + [str(binary)], env=env, text=True))
                built_digest = sha(binary)
                cell, output = run(sanitizer + '-consumer-run', [binary])
                assert sha(binary) == built_digest, 'Consumer binary changed during execution'
                events = []
                for line in output.splitlines():
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        pass
                assert len(events) == 1
                result = events[0]
                assert result['passed'] is True and result['scope'] == 'kernel-and-memory-codec-only'
                for field, value in dict(model_completions=2, memory_exchanges=2, model_idle_reuses=1,
                                         foreign_owner_checks=2, close_rejections=2).items():
                    assert type(result[field]) is int and result[field] == value
                assert type(result['work1_calls']) is int and result['work1_calls'] > 2
                assert result['scope_zero'] is True and result['heap_zero'] is True
                cell.update(result=result, binary_sha256=sha(binary))
            state['source_after'] = manifest(source, state['source_before'])
            state['copy_after'] = manifest(copied)
            assert state['source_before'] == state['source_after'] == state['copy_before'] == state['copy_after']
        assert sha(compiler) == state['compiler']['sha256']
        assert sha(helper) == state['closure_helper']['sha256'] and sha(__file__) == state['gate_sha256']
        assert standard_sources(stdlib) == state['compiler']['standard_sources']
        assert len(state['checks']) == 8
        state['artifact_sha256'] = {str(p): sha(p) for p in sorted(artifacts.rglob('*')) if p.is_file()}
        state['passed'] = True
    except Exception as error:
        state['error'] = repr(error)
    finally:
        report.write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps(dict(passed=state['passed'], checks=len(state['checks']), report=str(report), error=state.get('error'))))
    return 0 if state['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
