#!/usr/bin/env python3
"""One source-bound paired gate for three independent redirect foundations."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

STREAMS = {
    'ledger': 'async/redirect_kernel_test.odin',
    'prepare': 'async/redirect_prepare_test.odin',
    'queue': 'async/redirect_queue_test.odin',
}
API_FILES = ['async/redirect_types.odin', 'async/redirect_kernel.odin',
             'async/redirect_prepare.odin', 'async/redirect_allocator.odin', 'async/network_queue.odin']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def manifest(root, names=None):
    root = Path(root)
    names = names if names is not None else sorted(
        str(p.relative_to(root)) for p in root.rglob('*')
        if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts)
    result = {}
    for name in names:
        path = root/name
        require(path.is_file() and not path.is_symlink(), 'Nonphysical source closure: '+str(path))
        result[name] = digest(path)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--odin', type=Path, required=True)
    p.add_argument('--core-root', type=Path, required=True)
    p.add_argument('--shared-root', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--sanitizers', nargs='+', choices=['address','thread'], default=['address','thread'])
    a = p.parse_args()
    require(len(a.sanitizers)==len(set(a.sanitizers)), 'Duplicate sanitizer selection')
    compiler,core,shared,report=[path.resolve() for path in (a.odin,a.core_root,a.shared_root,a.report)]
    report.parent.mkdir(parents=True,exist_ok=True)
    surf=shared/'surf'
    env=dict(os.environ,ODIN_ROOT=str(core))
    env['PATH']='/opt/homebrew/opt/llvm@22/bin:'+env.get('PATH','')
    for key in list(env):
        if key.startswith(('AWS_','GOOGLE_','GCLOUD_','AZURE_')):
            del env[key]
    state={'passed':False,'scope':'Independent pure accepted-hop ledger, redirect preparation and finite DNS allowance tests; no actor, network or public redirect execution claim',
           'selected_sanitizers':a.sanitizers,'checks':[],'streams':{},'native_execution_count':0,'skipped':[]}

    def run(label,command):
        command=[str(x) for x in command]
        started=time.monotonic()
        cell={'name':label,'command':command}
        state['checks'].append(cell)
        try:
            done=subprocess.run(command,env=env,text=True,capture_output=True,timeout=180)
            output=done.stdout+done.stderr
            cell.update(returncode=done.returncode,stdout=done.stdout,stderr=done.stderr)
        except (OSError,subprocess.TimeoutExpired) as error:
            output=str(error);cell.update(returncode=None,error=type(error).__name__)
        log=report.parent/(label+'.log');log.write_text(output)
        cell.update(log=str(log),log_sha256=digest(log),seconds=time.monotonic()-started)
        require(cell['returncode']==0,label+' failed: '+str(log))
        require('+++ leak' not in output and '+++ bad free' not in output,label+' memory diagnostics')
        return output

    try:
        state['compiler']={'path':str(compiler),'sha256':digest(compiler),'version':run('compiler-version',[compiler,'version']).strip(),'core_root':str(core)}
        clang=Path(shutil.which('clang',path=env['PATH'])).resolve()
        state['clang']={'path':str(clang),'sha256':digest(clang),'version':run('clang-version',[clang,'--version']).splitlines()[0]}
        names=[]
        for stream,path in STREAMS.items():
            source=surf/path
            discovered=re.findall(r'@\(test\)\s*(\w+)\s*::\s*proc\b',source.read_text())
            require(discovered,stream+' has no executable aggregate')
            state['streams'][stream]={'path':path,'source_sha256':digest(source),'test_names':discovered,'aggregate_count':len(discovered)}
            names.extend(discovered)
        require(len(names)==len(set(names)),'Duplicate aggregate names')
        state['expected_aggregate_count']=len(names)
        state['requested_test_names']=names
        artifacts=[*STREAMS.values(),*API_FILES,'tests/redirect_foundations101.py']
        state['owned_sources_before']=manifest(surf,artifacts)
        state['runner_sha256']=digest(__file__)
        standard=sorted(str(path.relative_to(core)) for folder in ('base','core','vendor')
                        for path in (core/folder).rglob('*') if path.is_file() and path.suffix in ('.odin','.h','.c','.s','.S'))
        state['core_sources_before']=manifest(core,standard)
        helper=compiler.parent/'ci/webtools_consumer_gate.py'
        state['closure_helper_sha256']=digest(helper)
        spec=importlib.util.spec_from_file_location('redirect_foundations_closure',helper)
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-redirect-foundations-') as temporary:
            copied=Path(temporary)/'shared';copied.mkdir()
            state['closure']=gate.copy_closure('surf/async',shared,copied)
            state['copied_sources_before']=manifest(copied)
            state['source_closure_before']=manifest(shared,state['copied_sources_before'])
            require(state['copied_sources_before']==state['source_closure_before'],'Physical closure mismatch')
            state['binaries_before']={}
            for sanitizer in a.sanitizers:
                binary=report.parent/('redirect-foundations-'+sanitizer)
                output=run('focused-'+sanitizer,[compiler,'test',copied/'surf/async',
                    '-collection:shared='+str(copied),'-warnings-as-errors','-thread-count:1',
                    '-define:ODIN_TEST_THREADS=1','-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true',
                    '-define:ODIN_TEST_LOG_STATE_CHANGES=true','-define:ODIN_TEST_NAMES='+','.join(names),
                    '-sanitize:'+sanitizer,'-keep-executable','-out:'+str(binary)])
                actual=re.findall(r'Finished (\d+) tests? in ',output)
                require(actual==[str(len(names))] and 'All tests were successful' in output,'Wrong actual aggregate count for '+sanitizer)
                require(all(name in output for name in names),'Missing executed-name state trace for '+sanitizer)
                state['checks'][-1].update(aggregate_count=len(names),executed_test_names=names)
                state['binaries_before'][str(binary)]=digest(binary)
            state['copied_sources_after']=manifest(copied)
            state['source_closure_after']=manifest(shared,state['copied_sources_before'])
            require(state['copied_sources_before']==state['copied_sources_after']==state['source_closure_after'],'Source/copy closure changed during paired gate')
        state['owned_sources_after']=manifest(surf,artifacts)
        state['core_sources_after']=manifest(core,standard)
        state['binaries_after']={path:digest(path) for path in state['binaries_before']}
        require(state['owned_sources_before']==state['owned_sources_after'],'Owned API/test sources changed during gate')
        require(state['core_sources_before']==state['core_sources_after'],'Core source closure changed during gate')
        require(state['binaries_before']==state['binaries_after'],'Paired executable changed')
        require(state['compiler']['sha256']==digest(compiler) and state['clang']['sha256']==digest(clang) and
                state['closure_helper_sha256']==digest(helper) and state['runner_sha256']==digest(__file__),'Toolchain/runner/helper changed')
        state['passed']=True
    except Exception as error:
        state['failure']=str(error)
        raise
    finally:
        report.write_text(json.dumps(state,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'passed':True,'aggregate_count':len(names),'sanitizers':a.sanitizers,'report':str(report)}))


if __name__=='__main__':
    main()
