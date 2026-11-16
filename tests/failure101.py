#!/usr/bin/env python3
"""Physical-copy public submit/redirect failure and late-owner lifetime gate.

The separately sealed constructor414 matrix remains a prerequisite. This gate
injects only allocations after public submission and after a literal307 arrives.
"""
from staging import copy_closure, test_run, test_files
import argparse,hashlib,importlib.util,json,os,re,select,shutil,signal,subprocess,tempfile,time
from pathlib import Path

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(v,message):
 if not v:raise RuntimeError(message)
def manifest(root,names=None):
 root=Path(root)
 if names is None:names=sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts)
 result={}
 for n in names:
  p=root/n;require(p.is_file() and not p.is_symlink(),'nonphysical source '+str(p));result[n]=sha(p)
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('odin','core-root','shared-root','report'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--sanitizers',nargs='+',choices=['address','thread'],default=['address','thread'])
 parser.add_argument('--baseline-only',action='store_true',help='Explicitly partial diagnostic; omits redirect fault matrix')
 a=parser.parse_args();require(len(set(a.sanitizers))==len(a.sanitizers),'duplicate sanitizer')
 compiler,core,shared,report=[v.resolve() for v in (a.odin,a.core_root,a.shared_root,a.report)]
 report.parent.mkdir(parents=True,exist_ok=True);own=Path(__file__).resolve().parents[1]
 fixtures=['async/tests/internal/failure_test.odin','tests/failure101.py','tests/testdata/failure101/main.odin','tests/testdata/failure101/peer.go']
 state={'passed':False,'scope':'public fixed-body submit/redirect allocation failures, callback-safe close/cancel/stats and whole-backed Response lifetime; constructor414 referenced, no new constructor claim','selected_sanitizers':a.sanitizers,'partial':a.baseline_only or set(a.sanitizers)!={'address','thread'},'commands':[],'cells':[],'native_execution_count':0,'artifact_hashes':{}}
 env=dict(os.environ,ODIN_ROOT=str(core),GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',CGO_ENABLED='0',GOCACHE=str(report.parent/'go-cache'));env['PATH']='/opt/homebrew/opt/llvm@22/bin:'+env.get('PATH','')
 for k in list(env):
  if k.startswith(('AWS_','GOOGLE_','GCLOUD_','AZURE_')):del env[k]
 def run(label,command,timeout=180):
  command=[str(c) for c in command];start=time.monotonic();row={'name':label,'command':command};state['commands'].append(row)
  try:
   done=test_run(command,env=env,capture_output=True,text=True,timeout=timeout);text=done.stdout+done.stderr;row.update(returncode=done.returncode,stdout=done.stdout,stderr=done.stderr)
  except (OSError,subprocess.TimeoutExpired) as e:text=str(e);row.update(returncode=None,error=type(e).__name__)
  log=report.parent/(label+'.log');log.write_text(text);row.update(log=str(log),log_sha256=sha(log),seconds=time.monotonic()-start)
  require(row['returncode']==0,label+' failed '+str(log));require('+++ leak' not in text and '+++ bad free' not in text,label+' ownership diagnostic');return text
 try:
  state['compiler']={'path':str(compiler),'sha256':sha(compiler),'version':run('compiler-version',[compiler,'version']).strip(),'root':str(core)}
  go=Path(shutil.which('go',path=env['PATH'])).resolve();state['go']={'path':str(go),'sha256':sha(go),'version':run('go-version',[go,'version']).strip()}
  std=sorted(str(p.relative_to(core)) for d in ('base','core','vendor') for p in (core/d).rglob('*') if p.is_file() and p.suffix in ('.odin','.h','.c','.s','.S'))
  state['standard_sources_before']=manifest(core,std);state['fixture_sources_before']=manifest(own,fixtures)
  helper=compiler.parent/'ci/webtools_consumer_gate.py';state['closure_helper_sha256']=sha(helper)
  spec=importlib.util.spec_from_file_location('failure_closure',helper);gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
  with tempfile.TemporaryDirectory(prefix='surf101-failure32-') as tmp:
   temp=Path(tmp);copied=temp/'shared';copied.mkdir();state['closure']=copy_closure(gate, 'surf/async',shared,copied)
   original=manifest(copied);state['source_files_before']=manifest(shared,original);require(original==state['source_files_before'],'copy differs from source')
   # Supports a temporary independent draft without writing the candidate.
   shutil.copyfile(own/'async/tests/internal/failure_test.odin',copied/'surf/async/tests/internal/failure_test.odin')
   state['copied_files_before']=manifest(copied);state['unit_overlay_sha256']=sha(copied/'surf/async/tests/internal/failure_test.odin')
   host=temp/'host';host.mkdir();shutil.copyfile(own/'tests/testdata/failure101/main.odin',host/'main.odin')
   peer=report.parent/'peer';run('peer-build',[go,'build','-o',peer,own/'tests/testdata/failure101/peer.go']);state['artifact_hashes'][str(peer)]=sha(peer)
   names=['failure32_public_submit_grants_preserve_full_caller_inputs_and_rollback','failure32_closed_scope_rejects_before_new_allocation_and_refunds_lease','failure32_allocation_callbacks_use_public_close_stats_cancel_and_fresh_clock']
   for san in a.sanitizers:
    flags=['-collection:shared='+str(copied),'-warnings-as-errors','-thread-count:1','-sanitize:'+san]
    unit=report.parent/('units-'+san)
    output=run('units-'+san,[compiler,'test',copied/'surf/async',*flags,'-define:ODIN_TEST_THREADS=1','-define:ODIN_TEST_NAMES='+','.join(names),'-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true','-keep-executable','-out:'+str(unit)])
    require(re.findall(r'Finished (\d+) tests? in ',output)==['3'] and 'All tests were successful' in output,'unit aggregate count');state['artifact_hashes'][str(unit)]=sha(unit)
    binary=report.parent/('native-'+san);run('host-build-'+san,[compiler,'build',host,*flags,'-out:'+str(binary)]);state['artifact_hashes'][str(binary)]=sha(binary)
    def cell(point,mode):
     label=f'{san}-p{point}-m{mode}';directory=temp/label
     proc=subprocess.Popen([str(peer),'-dir',str(directory)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
     try:
      require(select.select([proc.stdout],[],[],10)[0],label+' readiness timeout');endpoint=proc.stdout.readline().strip();require(endpoint.startswith('127.0.0.1:'),label+' endpoint')
      output=run(label,[binary,endpoint,directory,point,mode],25);state['native_execution_count']+=1
      rows=[json.loads(v) for v in output.splitlines() if v.startswith('{')];require(len(rows)==1,label+' native summary');native=rows[0]
      for fact in ('header_freed','heap_zero','scope_zero','fd_zero'):require(native[fact] is True,label+' '+fact)
      out,err=proc.communicate(timeout=5);log=report.parent/(label+'-peer.log');log.write_text(out+err);require(proc.returncode==0,label+' peer failed '+str(log));rows=[json.loads(v) for v in out.splitlines() if v.startswith('{')];require(len(rows)==1,label+' peer summary');oracle=rows[0];events=oracle['events']
      require([e['path'] for e in events] in (['/A'],['/A','/final']),label+' ambiguous retry/wire order');require(all(e['body']=='fixed-owned-payload' for e in events),label+' body not preserved')
      require(oracle['connections']==len(events) and len({e['connection'] for e in events})==len(events),label+' physical redirect retirement')
      if mode==0:require(native['error']=='None' and len(events)==2 and native['hits']==0,label+' healthy redirect')
      else:
       require(native['hits']==1,label+' injection not executed')
       if mode<=6:require(native['error']=='Allocation_Failed',label+' allocation cause replaced')
       elif mode==7:require(native['error']=='Allocation_Failed' and native['budget']=='Closed' and native['phase']=='Protocol',label+' exact closed scope cause')
       else:require(native['error']=='IO_Failed' and native['transport']=='Cancelled' and native['phase']=='Cancellation',label+' cancellation cause')
      state['cells'].append({'name':label,'point':point,'mode':mode,'native':native,'peer':oracle,'peer_log':str(log),'peer_log_sha256':sha(log)})
      return native
     finally:
      if proc.poll() is None:
       os.killpg(proc.pid,signal.SIGTERM)
       try:proc.communicate(timeout=5)
       except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()
    base=cell(0,0);require(base['calls']==len(base['sizes'])==len(base['alignments']) and base['calls']>0,'baseline allocation census')
    if not a.baseline_only:
     for point,alignment in enumerate(base['alignments'],1):
      require(alignment>1,'unexpected byte-aligned raw managed grant; update negative oracle explicitly')
      for mode in range(1,7):cell(point,mode)
     for mode in (7,8,9):cell(4,mode)
    actual={(c['point'],c['mode']) for c in state['cells'] if c['name'].startswith(san+'-')}
    expected={(0,0)}
    if not a.baseline_only:expected|={(point,mode) for point in range(1,base['calls']+1) for mode in range(1,7)}|{(4,mode) for mode in (7,8,9)}
    rows=[c for c in state['cells'] if c['name'].startswith(san+'-')]
    require(actual==expected and len(rows)==len(expected),'missing/duplicate required allocation or callback cell')
   state['copied_files_after']=manifest(copied);state['source_files_after']=manifest(shared,state['source_files_before']);state['fixture_sources_after']=manifest(own,fixtures);state['standard_sources_after']=manifest(core,std)
   for before,after in [('source_files_before','source_files_after'),('copied_files_before','copied_files_after'),('fixture_sources_before','fixture_sources_after'),('standard_sources_before','standard_sources_after')]:require(state[before]==state[after],before+' changed')
   require(sha(host/'main.odin')==state['fixture_sources_before']['tests/testdata/failure101/main.odin'],'native source changed')
  require(state['native_execution_count']==len(state['cells']),'native cell count mismatch')
  state['artifact_hashes_after']={p:sha(p) for p in state['artifact_hashes']};require(state['artifact_hashes']==state['artifact_hashes_after'],'binary changed');state['passed']=True
 except Exception as error:state['error']=str(error);raise
 finally:
  state['log_hashes']={str(p):sha(p) for p in sorted(report.parent.glob('*.log'))};report.write_text(json.dumps(state,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'passed':True,'native_execution_count':state['native_execution_count'],'report':str(report)}))
if __name__=='__main__':main()
