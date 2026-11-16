#!/usr/bin/env python3
"""Independent real Actor/Runtime fixture; never public Client.init evidence."""
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

MODES = ('healthy','stale','partial','close','setup-deadline','body-deadline',
         'cancel-read','cancel-mailbox','uncertain','one-worker','lifetime','reuse-waiter')
CASES = {transport+'-'+mode:(transport=='tls',mode) for transport in ('tcp','tls') for mode in MODES}

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value: raise RuntimeError(message)
def manifest(root,names=None):
    root=Path(root)
    if names is None:
        names=sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts)
    result={}
    for name in names:
        p=root/name
        require(p.is_file() and not p.is_symlink(),'nonphysical source '+str(p))
        result[name]=sha(p)
    return result

def verify(label,encrypted,mode,native,peer):
    completion=[r for r in native if r.get('event')=='completion']
    summaries=[r for r in native if r.get('event')=='summary']
    cleanup=[r for r in native if r.get('event')=='cleanup']
    require(len(summaries)==1 and cleanup==[{'event':'cleanup','heap_zero':True,'fd_delta':0}],label+' cleanup proof')
    summary=summaries[0]
    expected=3 if mode in ('stale','partial','close') else 2 if mode in ('healthy','cancel-read','one-worker','reuse-waiter') else 1
    require(len(completion)==expected and summary['completed']==expected,label+' completion count')
    require(len({r['label'] for r in completion})==expected,label+' duplicate completion')
    require(summary['fixture_controller'] is True and summary['public_client_init'] is False and summary['scope_zero'] is True,label+' fixture scope')
    require(summary['pin0']>0 and summary['resumes0']>0 and summary['fixture_prepin'] is False,label+' unassisted owner-thread witness')
    bylabel={r['label']:r for r in completion}
    facts=peer.get('requests') or []
    events=peer.get('events') or []
    dns=peer.get('dns') or []
    require(peer['tls']==encrypted and peer['mode']==mode,label+' independent peer identity')
    if encrypted:
        for event in events:
            if event['event']=='handshake':
                require(event['version']==772 and event['alpn']=='http/1.1',label+' authenticated TLS13/ALPN')
                require(event['server_name'] in ('actor.test','cheap.actor.test'),label+' URL-derived SNI')
    if mode=='healthy':
        require(summary['old_cutoff_expired'] and summary['late_response_survived_state_free'],label+' retained owner/expired A proof')
        require([r['path'] for r in facts]==['/A','/B'] and peer['connections']==1 and len(dns)==1,label+' genuine same connection')
        require(bylabel['A']['connection']==bylabel['B']['connection'] and bylabel['B']['kind']=='None',label+' same physical generation')
        require(bylabel['A']['cutoff']<bylabel['B']['cutoff'],label+' request budget rotation')
    elif mode in ('stale','partial','close'):
        require(summary['old_cutoff_expired'],label+' old A cutoff')
        require(bylabel['B']['kind']!='None' and bylabel['B']['effect']=='Not_Sent',label+' B must fail without replay')
        require([r['path'] for r in facts]==['/A','/C'] and peer['connections']==2,label+' no B on old/new transport')
        require(bylabel['C']['kind']=='None' and bylabel['A']['connection']!=bylabel['C']['connection'],label+' fresh C generation')
        if mode=='stale': require(summary['workers']==2 and summary['fixture_helper_done']==1 and summary['fixture_helper_thread']>0 and summary['fixture_helper_thread']!=summary['pin0'],label+' actual two-worker owner stability')
        if mode=='partial':
            kind='partial_record_staged' if encrypted else 'partial_raw_staged'
            staged=[r for r in events if r['event']==kind]
            require(len(staged)==1 and staged[0]['bytes']==1,label+' actual one-byte staging')
            if encrypted: require(staged[0]['record_type']==23 and staged[0]['full_bytes']>5,label+' partial encrypted record')
    elif mode=='setup-deadline':
        require(bylabel['A']['phase']=='Deadline' and bylabel['A']['kind']!='None',label+' setup total cutoff')
        require(len(dns)>=1 and any(e['event']=='dns_reply' for e in events),label+' actual delayed DNS')
        require(any(e['event']=='server_record_held' for e in events),label+' actual delayed peer bytes')
        if encrypted: require(peer['handshakes']==0 and not facts and bylabel['A']['effect']=='Not_Sent',label+' no HTTP before TLS cutoff')
    elif mode=='body-deadline':
        require(bylabel['A']['phase']=='Deadline' and bylabel['A']['status']==200 and bylabel['A']['effect']=='Response_Received',label+' body total cutoff')
        require(any(e['event']=='body_held' for e in events) and len(dns)>=1,label+' DNS and body stages observed')
    elif mode=='lifetime':
        require(bylabel['A']['phase']=='Deadline' and bylabel['A']['status']==200 and bylabel['A']['effect']=='Response_Received',label+' lifetime keeps received status')
        require(summary['lifetime_cutoff']==bylabel['A']['cutoff']<bylabel['A']['requested_cutoff'],label+' immutable lifetime caps request')
        require(any(e['event']=='body_held' for e in events),label+' actual peer header/body boundary')
    elif mode=='reuse-waiter':
        balance=[r for r in native if r.get('event')=='dns_balanced']
        require(balance==[{'event':'dns_balanced','reserved':32,'burned':32}],label+' unnecessary reused snapshot draws burned')
        require([r['path'] for r in facts]==['/A','/B'] and peer['connections']==1 and len(dns)==1,label+' waiter reused same physical connection')
    elif mode=='cancel-read':
        require(bylabel['A']['phase']=='Cancellation' and bylabel['B']['kind']=='None',label+' request-only cancellation')
        require(peer['connections']==2 and [r['path'] for r in facts]==['/A','/B'],label+' cancellation fresh generation')
    elif mode=='cancel-mailbox':
        require(bylabel['A']['phase']=='Cancellation' and bylabel['A']['effect']=='Not_Sent',label+' pending mailbox cancel')
        require(peer['connections']==0 and not facts and not dns,label+' no setup for canceled mailbox')
        draws=[r for r in native if r.get('event')=='mailbox_draws']
        require(len(draws)==1 and draws[0]['remaining']==0 and draws[0]['burned']>=16,label+' pending mailbox draw disposal')
    elif mode=='uncertain':
        require(bylabel['A']['kind']!='None' and bylabel['A']['effect']=='Unknown',label+' ambiguous write must stay unknown')
        require(peer['connections']==1 and len(facts)==1 and facts[0]['method']=='POST' and facts[0]['body_bytes']==1,label+' uncertain write no automatic replay')
        require(any(e['event']=='uncertain_post_reset' and e['body_first']==112 for e in events),label+' cloned source survives poison/free')
    elif mode=='one-worker':
        require(summary['workers']==1 and summary['pin0']==summary['pin1'] and summary['resumes1']>0,label+' same actual worker')
        require([r['label'] for r in completion]==['B','A'],label+' cheap request progresses before held body')
        require(bylabel['A']['kind']==bylabel['B']['kind']=='None' and peer['connections']==2,label+' both actual responses')
        responses=[r['path'] for r in events if r['event']=='response']
        require(responses==['/B','/A'],label+' independent peer progress order')
    for record in completion:
        if record['phase']=='Deadline': require(record['completed_at']>=record['cutoff'],label+' deadline witness')
        if record['kind']=='None': require(record['status']==200 and record['body']==ord(record['label']),label+' exact response')
    return {'completions':completion,'summary':summary,'cleanup':cleanup[0],'peer':peer}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('odin','core-root','shared-root','report'): parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--sanitizers',nargs='+',choices=('address','thread'),default=['address','thread'])
    parser.add_argument('--case',action='append',choices=tuple(CASES))
    args=parser.parse_args()
    compiler,core,shared,report=[p.resolve() for p in (args.odin,args.core_root,args.shared_root,args.report)]
    require(len(args.sanitizers)==len(set(args.sanitizers)),'duplicate sanitizer')
    selected=args.case or list(CASES);require(len(selected)==len(set(selected)),'duplicate case')
    report.parent.mkdir(parents=True,exist_ok=True)
    state={'passed':False,'scope':'Real Actor18 with fixture Kernel controller/Runtime group publication; not Client.init or full101 proof','native_execution_count':0,'commands':[],'cells':[],'selected_cases':selected,'selected_sanitizers':args.sanitizers,'skipped':[]}
    env=dict(os.environ,ODIN_ROOT=str(core),GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0')
    env['PATH']='/opt/homebrew/opt/llvm@22/bin:'+env.get('PATH','');env['GOCACHE']=str(report.parent/'go-cache')
    for key in list(env):
        if key.startswith(('AWS_','GOOGLE_','GCLOUD_','AZURE_')):del env[key]
    def run(name,command,timeout=120):
        command=list(map(str,command));started=time.monotonic()
        cell={'name':name,'command':command,'returncode':None};state['commands'].append(cell)
        log=report.parent/(name+'.log')
        try:
            process=test_run(command,env=env,capture_output=True,text=True,timeout=timeout)
            text=process.stdout+process.stderr;cell['returncode']=process.returncode
        except (OSError,subprocess.TimeoutExpired) as error:
            def decode(value): return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
            text=decode(getattr(error,'stdout',None))+decode(getattr(error,'stderr',None))+str(error)
            cell['exception']=type(error).__name__;process=None
        log.write_text(text);cell.update(log=str(log),log_sha256=sha(log),seconds=time.monotonic()-started)
        require(cell['returncode']==0 and '+++ leak' not in text and '+++ bad free' not in text,name+' failed '+str(log))
        return process.stdout
    def stop(process):
        if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
        try:return process.communicate(timeout=3)
        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);return process.communicate(timeout=3)
    try:
        state['runner_sha256']=sha(__file__)
        state['compiler']={'path':str(compiler),'sha256':sha(compiler),'version':run('compiler-version',[compiler,'version']).strip()}
        state['go']={'version':run('go-version',['go','version']).strip(),'path':shutil.which('go',path=env['PATH'])}
        state['go']['sha256']=sha(state['go']['path'])
        standard=sorted(str(p.relative_to(core)) for tree in ('base','core','vendor') for p in (core/tree).rglob('*') if p.is_file() and p.suffix in ('.odin','.c','.h','.s','.S'))
        state['core_sources_before']=manifest(core,standard)
        fixture_names=['tests/session_actor101.py','tests/testdata/session_actor101/main.odin','tests/testdata/session_actor101/peer.go','async/tests/internal/session_test.odin']
        state['fixtures_before']=manifest(shared/'surf',fixture_names)
        helper=compiler.parent/'ci/webtools_consumer_gate.py';state['closure_helper_sha256']=sha(helper)
        spec=importlib.util.spec_from_file_location('actor_closure',helper);gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory(prefix='surf101-actor-') as tmp:
            temp=Path(tmp);copied=temp/'shared';copied.mkdir()
            state['closure']=copy_closure(gate, 'surf/async',shared,copied)
            state['copied_sources_before']=manifest(copied);state['source_closure_before']=manifest(shared,state['copied_sources_before'])
            require(state['copied_sources_before']==state['source_closure_before'],'physical closure mismatch')
            snapshots=report.parent/'executed-actor-source';snapshots.mkdir(exist_ok=True)
            state['executed_actor_sources']={}
            for name in ('session.odin','coordinator.odin','pool.odin'):
                source=copied/'surf/async'/name;destination=snapshots/name;shutil.copyfile(source,destination);state['executed_actor_sources'][name]=sha(destination)
            host=temp/'host';host.mkdir();shutil.copyfile(shared/'surf/tests/testdata/session_actor101/main.odin',host/'main.odin')
            peer=report.parent/'peer';run('peer-build',['go','build','-o',peer,shared/'surf/tests/testdata/session_actor101/peer.go']);run('peer-vet',['go','vet',shared/'surf/tests/testdata/session_actor101/peer.go']);state['peer_binary_sha256']=sha(peer)
            for sanitizer in args.sanitizers:
                binary=report.parent/('native-'+sanitizer)
                run('host-build-'+sanitizer,[compiler,'build',host,'-collection:shared='+str(copied),'-warnings-as-errors','-thread-count:1','-sanitize:'+sanitizer,'-out:'+str(binary)])
                state.setdefault('binary_hashes',{})[str(binary)]=sha(binary)
                state.setdefault('native_linkage',{})[sanitizer]=run('native-linkage-'+sanitizer,['otool','-L',binary])
                for selected_case in selected:
                    encrypted,mode=CASES[selected_case];label=sanitizer+'-'+selected_case;directory=temp/label
                    command=[str(peer),'-mode',mode,'-dir',str(directory)]+(['-tls'] if encrypted else [])
                    process=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
                    ready_line='';peer_log=report.parent/(label+'-peer.log')
                    try:
                        require(select.select([process.stdout],[],[],8)[0],label+' readiness timeout')
                        ready_line=process.stdout.readline();ready=json.loads(ready_line);require(ready.get('event')=='ready',label+' readiness')
                        state['native_execution_count']+=1
                        state.setdefault('native_execution_attempts',[]).append(label)
                        output=run(label,[binary,ready['tcp'],ready['dns'],mode,'tls' if encrypted else 'tcp',directory],timeout=25)
                        stdout,stderr=process.communicate(timeout=5);peer_log.write_text(ready_line+stdout+stderr)
                        require(process.returncode==0,label+' peer failed')
                        native=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
                        peer_rows=[json.loads(line) for line in stdout.splitlines() if line.startswith('{')]
                        summaries=[r for r in peer_rows if r.get('event')=='summary'];require(len(summaries)==1,label+' peer summary')
                        proof=verify(label,encrypted,mode,native,summaries[0]);state['cells'].append({'name':label,'passed':True,'proof':proof,'peer_log':str(peer_log),'peer_log_sha256':sha(peer_log)})
                        require(sha(binary)==state['binary_hashes'][str(binary)] and sha(peer)==state['peer_binary_sha256'],label+' binary changed')
                    finally:
                        stdout,stderr=stop(process)
                        if not peer_log.exists():peer_log.write_text(ready_line+stdout+stderr)
            state['copied_sources_after']=manifest(copied);state['source_closure_after']=manifest(shared,state['copied_sources_before'])
            require(state['copied_sources_before']==state['copied_sources_after']==state['source_closure_after'],'closure source changed')
        state['fixtures_after']=manifest(shared/'surf',fixture_names);state['core_sources_after']=manifest(core,standard)
        require(state['fixtures_before']==state['fixtures_after'] and state['core_sources_before']==state['core_sources_after'],'fixture/core source changed')
        require(state['runner_sha256']==sha(__file__) and state['compiler']['sha256']==sha(compiler) and state['closure_helper_sha256']==sha(helper) and state['go']['sha256']==sha(state['go']['path']),'toolchain/runner changed')
        expected={san+'-'+case for san in args.sanitizers for case in selected}
        require(len(state['cells'])==len(expected) and {c['name'] for c in state['cells']}==expected,'missing/duplicate cells')
        state['selected_matrix_passed']=True
        state['complete_matrix']=set(args.sanitizers)=={'address','thread'} and set(selected)==set(CASES)
        state['passed']=state['complete_matrix']
    finally:
        state['log_hashes']={str(p):sha(p) for p in sorted(report.parent.glob('*.log'))}
        report.write_text(json.dumps(state,indent=2)+'\n')
    print(json.dumps({'passed':state['passed'],'selected_matrix_passed':state.get('selected_matrix_passed',False),'actual_native_cells':state['native_execution_count'],'report':str(report)}))
if __name__=='__main__':main()
