#!/usr/bin/env python3
"""Run physical-copy public prerequisite consumers; full Surf101 remains open."""
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

PUBLIC_CONSUMER = r'''package main
import adapter "shared:async/connection"
import async "shared:async"
import surf "shared:surf"
import h1 "shared:http/v1"
import "base:intrinsics"
import rt "base:runtime"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:time"

State :: struct {runtime:async.Runtime,task:async.Task,loop:adapter.Executor,done:int}
resume :: proc(data:rawptr)->async.Resume_Result {
 s:=cast(^State)data
 assert(async.is_current_task(&s.task))
 assert(adapter.init_executor(&s.loop,&s.runtime,&s.task).kind==.None)
 first:=async.deadline_after(&s.runtime,time.Second)
 assert(adapter.set_request_budget(&s.loop,first).kind==.None)
 assert(adapter.wall_budget(&s.loop)!=(time.Time{}))
 bad:=first;bad.epoch+=1
 assert(adapter.set_request_budget(&s.loop,bad).kind==.Invalid_Config)
 second:=async.deadline_after(&s.runtime,2*time.Second)
 assert(adapter.set_request_budget(&s.loop,second).kind==.None)
 assert(adapter.budget_error(&s.loop).kind==.None)
 assert(adapter.set_request_budget(&s.loop,{}).kind==.None)
 assert(adapter.wall_budget(&s.loop)==(time.Time{}))
 return .Done
}
cancel :: proc(data:rawptr)->async.Resume_Result {return .Done}
complete :: proc(data:rawptr) {s:=cast(^State)data;intrinsics.atomic_store(&s.done,1)}
Fixture :: struct {at,written:int}
read :: proc(data:rawptr,dst:[]u8)->(int,net.Connection_Error) {
 f:=cast(^Fixture)data
 wire:="HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
 if f.at==len(wire) {return 0,{kind=.Peer_Closed}}
 n:=copy(dst,wire[f.at:]);f.at+=n;return n,{}
}
write :: proc(data:rawptr,src:[]u8)->(int,net.Connection_Error) {
 f:=cast(^Fixture)data;f.written+=len(src);return len(src),{}
}
close :: proc(data:rawptr)->net.Connection_Error {return {}}
main :: proc() {
 track:mem.Tracking_Allocator
 mem.tracking_allocator_init(&track,rt.heap_allocator(),rt.heap_allocator())
 allocator:=mem.tracking_allocator(&track)
 s:State
 assert(async.init(&s.runtime,{workers=1,task_capacity=1,io_capacity=0,allocator=allocator}).kind==.None)
 s.task={resume=resume,on_cancel=cancel,on_done=complete,data=&s}
 assert(async.spawn(&s.runtime,&s.task).kind==.None)
 assert(async.start(&s.runtime).kind==.None)
 assert(async.wait_idle(&s.runtime).kind==.None)
 assert(intrinsics.atomic_load(&s.done)==1)
 // on_done returns task ownership after automatic retirement.
 assert(async.unregister(&s.runtime,&s.task).kind==.Not_Registered)
 assert(async.destroy(&s.runtime).kind==.None)
 wire:[512]u8
 n,error:=h1.request_encode_content(wire[:],{method=.GET,url="http://example.test/"},.Keep_Alive,.Identity)
 assert(error.kind==.None)
 assert(string(wire[:n])=="GET / HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\nAccept-Encoding: identity\r\n\r\n")
 literal:="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
 head,used,decoded:=h1.response_header_decode(transmute([]u8)literal)
 assert(decoded.kind==.None && used==len(literal) && head.version=="HTTP/1.1")
 reusable,reuse_error:=h1.response_reuse_allowed(&head,"GET")
 assert(reuse_error.kind==.None && reusable)
 fixture:Fixture
 response,failure:=surf.exchange({data=&fixture,read=read,write=write,close=close},
  {method=.GET,url="https://fixture.invalid/"},8,allocator)
 assert(failure.kind==.None && response.status==200 && string(response.body)=="ok" && fixture.written>0)
 surf.response_destroy(&response)
 assert(track.current_memory_allocated==0 && len(track.allocation_map)==0 && len(track.bad_free_array)==0)
 mem.tracking_allocator_destroy(&track)
 fmt.println("FOUNDATIONS101 owner_budget=3 persistent_encode=1 reuse_metadata=1 facade_exchange=1 heap_zero=true")
}
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def manifest(root, names=None):
    root = Path(root)
    names = names if names is not None else sorted(
        str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    result = {}
    for name in names:
        path = root / name
        require(path.is_file() and not path.is_symlink(), 'Nonregular closure file: ' + str(path))
        result[name] = digest(path)
    return result


def standard_sources(root):
    return {str(p.relative_to(root)): digest(p) for tree in ('base', 'core', 'vendor')
            for p in sorted((root / tree).rglob('*.odin'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--sanitizers', nargs='+', choices=('address', 'thread'), default=['address', 'thread'])
    args = parser.parse_args()
    compiler = args.odin.resolve()
    stdlib = compiler.parent
    source = Path(__file__).resolve().parents[2]
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    helper = stdlib / 'ci/webtools_consumer_gate.py'
    state = {'passed': False, 'scope': '101 foundations only: public request cap, HTTP1 persistence and existing Surf facade; no async session/pool or cross-platform certification',
             'platform': platform.platform(), 'shared_source': str(source), 'sanitizers': args.sanitizers,
             'checks': [], 'skipped': [], 'gate_sha256': digest(Path(__file__))}
    env = dict(os.environ, ODIN_ROOT=str(stdlib))
    env['PATH'] = '/opt/homebrew/opt/llvm@22/bin' + os.pathsep + env.get('PATH', '')
    # Offline fixture execution requires no cloud credentials.
    for key in list(env):
        if key.startswith(('AWS_', 'GOOGLE_', 'GCLOUD_', 'AZURE_')):
            del env[key]

    def run(label, command, tests=None, timeout=120):
        start = time.monotonic()
        cell = {'name': label, 'command': [str(x) for x in command]}
        state['checks'].append(cell)
        try:
            completed = test_run(command, env=env, text=True, capture_output=True, timeout=timeout)
            text = completed.stdout + completed.stderr
            cell['returncode'] = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            text = str(error)
            cell.update(returncode=None, error=type(error).__name__)
        log = report.parent / (report.stem + '-' + label + '.log')
        log.write_text(text)
        cell.update(seconds=time.monotonic()-start, log=str(log), log_sha256=digest(log))
        require(cell['returncode'] == 0, label + ' failed: ' + str(log))
        require('+++ leak' not in text and '+++ bad free' not in text, label + ' ownership diagnostics')
        if tests is not None:
            counts = re.findall(r'Finished (\d+) tests? in ', text)
            require(counts == [str(tests)] and 'tests were successful' in text, label + ' test-count mismatch')
            cell['tests'] = tests
        return cell, text

    try:
        state['compiler'] = {'path': str(compiler), 'sha256': digest(compiler),
            'version': subprocess.check_output([compiler, 'version'], env=env, text=True).strip(),
            'stdlib_root': str(stdlib), 'stdlib_sources': standard_sources(stdlib)}
        state['closure_helper'] = {'path': str(helper), 'sha256': digest(helper)}
        spec = importlib.util.spec_from_file_location('foundations_consumer_closure', helper)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-foundation-consumers-') as temporary:
            work = Path(temporary)
            copied = work / 'shared'
            copied.mkdir()
            packages = ('surf', 'surf/tests', 'http/v1', 'async/connection', 'async/tests/connection')
            state['dependency_closures'] = {name: copy_closure(gate, name, source, copied) for name in packages}
            require(not any(p.is_symlink() for p in copied.rglob('*')), 'Copied closure contains a symlink')
            state['copied_files_before'] = manifest(copied)
            state['source_files_before'] = manifest(source, state['copied_files_before'])
            require(state['source_files_before'] == state['copied_files_before'], 'Physical-copy digest mismatch')
            app = work / 'app'
            app.mkdir()
            (app / 'main.odin').write_text(PUBLIC_CONSUMER)
            state['public_consumer_sha256'] = digest(app / 'main.odin')
            for sanitizer in args.sanitizers:
                binary = report.parent / (report.stem + '-public-' + sanitizer)
                build, _ = run('public-build-' + sanitizer, [compiler, 'build', app,
                    '-collection:shared=' + str(copied), '-thread-count:1', '-warnings-as-errors',
                    '-sanitize:' + sanitizer, '-out:' + str(binary)])
                build['binary_sha256'] = digest(binary)
                _, output = run('public-run-' + sanitizer, [binary])
                require(output.strip() == 'FOUNDATIONS101 owner_budget=3 persistent_encode=1 reuse_metadata=1 facade_exchange=1 heap_zero=true',
                        'Public consumer completion marker missing')
                for package, count in (('http/v1', 29), ('surf/tests', 29)):
                    binary = report.parent / (report.stem + '-' + package.replace('/', '-') + '-' + sanitizer)
                    cell, _ = run(package.replace('/', '-') + '-' + sanitizer, [compiler, 'test', copied / package,
                        '-collection:shared=' + str(copied), '-thread-count:1', '-warnings-as-errors',
                        '-define:ODIN_TEST_THREADS=1', '-sanitize:' + sanitizer, '-keep-executable', '-out:' + str(binary)], tests=count)
                    cell['binary_sha256'] = digest(binary)
            budget_report = report.parent / (report.stem + '-request-budget.json')
            run('request-budget-gate', ['python3', copied / 'async/tests/connection/request_budget_gate.py',
                '--odin', compiler, '--sanitizers', *args.sanitizers, '--report', budget_report], timeout=240)
            budget = json.loads(budget_report.read_text())
            require(budget['passed'] and len(budget['cells']) == 2 * len(args.sanitizers), 'Budget gate count/failure')
            require(all(c['returncode'] == 0 for c in budget['cells']), 'Budget tests incomplete')
            observed = sorted((next(arg for arg in c['command'] if arg.startswith('-sanitize:')), c['tests']) for c in budget['cells'])
            expected = sorted(('-sanitize:' + sanitizer, count) for sanitizer in args.sanitizers for count in (2, 5))
            require(observed == expected, 'Budget sanitizer/package coverage mismatch')
            state['request_budget_report'] = {'path': str(budget_report), 'sha256': digest(budget_report), 'actual_test_cells': len(budget['cells'])}
            state['source_files_after'] = manifest(source, state['source_files_before'])
            # The nested budget gate's Python import can produce __pycache__; it is
            # not source and must not obscure an actual copied source mutation.
            state['copied_files_after'] = manifest(copied)
            require(state['source_files_before'] == state['source_files_after'] == state['copied_files_after'], 'Source/copy changed during gate')
        require(digest(compiler) == state['compiler']['sha256'], 'Compiler changed during gate')
        require(digest(helper) == state['closure_helper']['sha256'], 'Closure helper changed during gate')
        require(digest(Path(__file__)) == state['gate_sha256'], 'Gate source changed during execution')
        require(standard_sources(stdlib) == state['compiler']['stdlib_sources'], 'Standard library changed during gate')
        state['passed'] = True
    except Exception as error:
        state['error'] = str(error)
    finally:
        report.write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps({'passed': state['passed'], 'checks': len(state['checks']), 'report': str(report), 'error': state.get('error')}))
    return 0 if state['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
