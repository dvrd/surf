#!/usr/bin/env python3
"""Validate scoped execution plans; this is not implementation validation."""
import collections,json,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parent
paths=[root/'plan101.yaml']
if (root/'phase-2-101.yaml').exists():paths.append(root/'phase-2-101.yaml')
subprocess.run(['ruby','-ryaml','-e','ARGV.each { |p| YAML.safe_load(File.read(p)) }',*map(str,paths)],check=True)
index=json.loads(paths[0].read_text());tasks=[]
for path in paths:
 d=json.loads(path.read_text());assert 0<len(d['tasks'])<=20
 tasks+=d['tasks']
ids={t['id'] for t in tasks};assert len(ids)==len(tasks)
counts=collections.Counter();rounds=collections.defaultdict(set);rc=collections.Counter();seen=set()
for task in tasks:
 assert 0<len(task['files'])<=5 and task['done_when'].strip()
 subprocess.run(['zsh','-n'],input=task['done_when'],text=True,check=True)
 assert set(task['depends_on'])<=ids
 keyround=task['round'];rc[keyround]+=1
 for name in task['files']:
  p=pathlib.Path(index['repositories'][task['repository']])/name
  assert p.exists() or p.parent.exists(),str(p)
  key=(task['repository'],name);assert key not in rounds[keyround],key
  rounds[keyround].add(key);counts[key]+=1
assert max(counts.values())<=2 and max(rc.values())<=5
while len(seen)<len(tasks):
 ready=[t['id'] for t in tasks if t['id'] not in seen and set(t['depends_on'])<=seen]
 assert ready,'dependency cycle';seen.update(ready)
for t in tasks:
 for dep in t['depends_on']:
  assert next(x for x in tasks if x['id']==dep)['round']<t['round']
print(json.dumps({'passed':True,'tasks':len(tasks),'rounds':len(rounds),'files':len(counts),'scope':'plan validation only'}))
