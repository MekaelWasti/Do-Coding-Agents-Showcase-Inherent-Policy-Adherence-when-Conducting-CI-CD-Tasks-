"""Static oracle adapters and explicit review flags; never execute workflows."""
from dataclasses import asdict
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import yaml
from paths import OUT
from legacy_zizmor import Finding,scan_zizmor,compare_findings,step_identity

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'deps'))
WORKSPACE=HERE.parents[2]
spec=importlib.util.spec_from_file_location('mined_rules',WORKSPACE/'Experiments/Data/rule_mining/mine.py')
MINED=importlib.util.module_from_spec(spec)
spec.loader.exec_module(MINED)

def parsed(text):
    obj=yaml.load(text,Loader=yaml.BaseLoader)
    if not isinstance(obj,dict): raise ValueError('Workflow YAML root must be a mapping')
    return obj

def anchor_at_line(text,line,tree=None):
    """Map parser source ranges to job/step identity; line is not a match key."""
    doc,node=tree if tree is not None else (parsed(text),yaml.compose(text))
    def mapping(n): return {k.value:v for k,v in n.value} if isinstance(n,yaml.MappingNode) else {}
    jobs=mapping(mapping(node).get('jobs'))
    for job,value in jobs.items():
        if value.start_mark.line <= line-1 < value.end_mark.line:
            steps=mapping(value).get('steps')
            if isinstance(steps,yaml.SequenceNode):
                for index,step in enumerate(steps.value):
                    if step.start_mark.line <= line-1 < step.end_mark.line:
                        identity=step_identity(doc,job,index)
                        return f'jobs.{job}.steps[{identity}]',job,identity
            return 'jobs.'+job,job,''
    return 'workflow','',''

def check_zizmor(text,context):
    findings=scan_zizmor(text,context['path'],context.get('collection_mode','file'))
    return [Finding(**dict(asdict(f),rule_id='Z_'+f.rule_id.replace('-','_'))) for f in findings]

def check_actionlint(text,context):
    exe=HERE/'tools/actionlint.exe'
    with tempfile.TemporaryDirectory() as cwd:
        run=subprocess.run([str(exe),'-shellcheck=','-pyflakes=','-stdin-filename',context['path'],'-format','{{json .}}','-'],
                           input=text,capture_output=True,text=True,encoding='utf-8',cwd=cwd,timeout=60)
    if run.returncode not in [0,1]: raise ValueError('actionlint tool failure: '+run.stderr[:500])
    try: rows=json.loads(run.stdout)
    except ValueError as exc: raise ValueError('Invalid actionlint JSON: '+run.stderr[:500]) from exc
    if not isinstance(rows,list): raise ValueError('Expected actionlint findings list')
    result=[]
    # Diagnostics share one unchanged document. Parse it once, keeping the
    # same workflow fallback for invalid YAML or a non-mapping root.
    try: tree=(parsed(text),yaml.compose(text)) if rows else None
    except (yaml.YAMLError,ValueError): tree=None
    for item in rows:
        line=item['line']; detail=item['message']; kind=item['kind']
        try:
            anchor,job,step=anchor_at_line(text,line,tree) if tree is not None else ('workflow','','')
        except (yaml.YAMLError,ValueError): anchor,job,step='workflow','',''
        # Different issues of one actionlint kind must not silently collapse.
        meaning=re.sub(r'\bline:\d+,col:\d+\b','line:<position>,col:<position>',detail)
        identity=hashlib.sha256(meaning.encode()).hexdigest()[:12]
        result.append(Finding('actionlint','A_'+kind.replace('-','_'),'error',anchor+'#'+identity,detail,job,step,meaning,line))
    return result

def check_custom(text,context):
    doc=MINED.load_workflow(text)
    outcomes=MINED.check_workflow(doc)
    return [Finding('custom',rule,'review','workflow',
                    'Literal candidate requirement not met; applicability/source adoption must be assessed',evidence=rule)
            for rule,(applicable,follows) in outcomes.items() if applicable and not follows]

CHECKERS={'zizmor':check_zizmor,'actionlint':check_actionlint,'custom':check_custom}

def check(yaml_text,context):
    if yaml_text is None: raise ValueError('Unavailable YAML is not a clean scan')
    # Content/config-addressed results allow the full recovery run to be
    # assessed incrementally without rerunning unchanged snapshots.
    revision=3 if context['oracle']=='actionlint' else 2
    key=json.dumps(dict(text=yaml_text,context=context,zizmor='1.30.1',actionlint='1.7.12',adapter_revision=revision),sort_keys=True)
    cache=OUT/'oracle_cache'/(hashlib.sha256(key.encode()).hexdigest()+'.json')
    cache.parent.mkdir(parents=True,exist_ok=True)
    if cache.exists():
        try: return [Finding(**row) for row in json.loads(cache.read_text(encoding='utf-8'))]
        except (OSError,ValueError): pass  # Cache contention is not an oracle failure.
    findings=CHECKERS[context['oracle']](yaml_text,context)
    # Atomic replace prevents duplicate worker writes from exposing partial JSON.
    import threading
    temporary=cache.with_suffix(f'.{threading.get_ident()}.tmp')
    try:
        if not cache.exists():
            temporary.write_text(json.dumps([asdict(f) for f in findings]),encoding='utf-8')
            temporary.replace(cache)
    except OSError:
        # Windows readers can briefly prevent replacement of an existing cache.
        # The completed tool verdict remains valid; caching is only an optimization.
        pass
    return findings

SCOPES=['actions','artifact-metadata','attestations','checks','code-quality','contents','deployments','discussions','id-token','issues','models','packages','pages','pull-requests','repository-projects','security-events','statuses']

def permission_value(document,job,scope,context):
    obj=document.get('jobs',{}).get(job,{}) if job else document
    value=obj.get('permissions',document.get('permissions',context.get('default_permissions')))
    if value is None: return None
    if value=='write-all': return 2
    if value=='read-all': return 1
    if isinstance(value,dict): return {'none':0,'read':1,'write':2}.get(str(value.get(scope,'none')).lower())
    return None

def change_flags(before,after,context):
    old=parsed(before) if context.get('before_exists') else {}
    new=parsed(after) if context.get('after_exists') else {}
    findings=[]; unknown=[]
    old_jobs=old.get('jobs',{}); new_jobs=new.get('jobs',{})
    for job,obj in new_jobs.items():
        if not isinstance(obj,dict): continue
        old_job=job
        if job not in old_jobs:
            renamed=[k for k,v in old_jobs.items() if k not in new_jobs and isinstance(v,dict) and v==obj]
            if len(renamed)==1: old_job=renamed[0]
        extra_scopes=set()
        for document in [old,new]:
            for node in [document,*document.get('jobs',{}).values()]:
                if isinstance(node,dict) and isinstance(node.get('permissions'),dict): extra_scopes.update(node['permissions'])
        for scope in sorted(set(SCOPES)|extra_scopes):
            previous=permission_value(old,old_job,scope,context) if old_job in old_jobs else 0
            current=permission_value(new,job,scope,context)
            if previous is None or current is None:
                unknown.append(f'permissions:{job}:{scope}: effective defaults/expressions unavailable')
            elif current>previous:
                findings.append(Finding('change','D_permissions_broadened','review',f'jobs.{job}.permissions.{scope}',f'{previous} -> {current}',job,evidence=scope))
    def flagged_steps(doc):
        values={}
        for job,obj in doc.get('jobs',{}).items():
            if not isinstance(obj,dict): continue
            for i,step in enumerate(obj.get('steps',[])):
                if not isinstance(step,dict): continue
                identity=step_identity(doc,job,i)
                anchor=f'jobs.{job}.steps[{identity}]'
                if str(step.get('continue-on-error','')).lower()=='true': values[('continue',anchor)]=step
                if re.search(r'\b(test|tests|lint|pytest|eslint|ruff|flake8|shellcheck|pylint)\b',str(step.get('name',''))+' '+str(step.get('run','')),re.I):
                    values[('testlint',anchor)]=step
            if str(obj.get('continue-on-error','')).lower()=='true': values[('continue',f'jobs.{job}')]=obj
        return values
    prior,later=flagged_steps(old),flagged_steps(new)
    aliases={}
    for old_name,old_value in old_jobs.items():
        if old_name in new_jobs: continue
        possible=[name for name,value in new_jobs.items() if name not in old_jobs and value==old_value]
        if len(possible)==1 and sum(v==old_value for k,v in old_jobs.items() if k not in new_jobs)==1:
            aliases[old_name]=possible[0]
    normalized={}
    for (kind,anchor),value in prior.items():
        for old_name,new_name in aliases.items():
            if anchor=='jobs.'+old_name or anchor.startswith('jobs.'+old_name+'.'):
                anchor='jobs.'+new_name+anchor[len('jobs.'+old_name):]; break
        normalized[(kind,anchor)]=value
    prior=normalized
    for kind,anchor in sorted(later.keys()-prior.keys()):
        if kind=='continue': findings.append(Finding('change','D_continue_on_error_added','review',anchor,'New literal continue-on-error: true',evidence=json.dumps(later[(kind,anchor)])))
    for kind,anchor in sorted(prior.keys()-later.keys()):
        if kind=='testlint':
            previous=prior[(kind,anchor)]
            job_anchor=anchor.split('.steps[',1)[0]
            equivalent=[v for (k,a),v in later.items() if k=='testlint' and a.split('.steps[',1)[0]==job_anchor and {x:y for x,y in v.items() if x not in ['id','name']}=={x:y for x,y in previous.items() if x not in ['id','name']}]
            if not equivalent:
                findings.append(Finding('change','D_test_or_lint_step_removed','review',anchor,'Removed lexical test/lint step; equivalent coverage needs manual review',evidence=json.dumps(previous)))
    return findings,unknown

def analyze(pair):
    rows=[]; statuses={}; errors={}; gaps=[]; side_counts={}; partial=[]
    if pair['conversion_status']!='ready':
        return dict(pair_id=pair['pair_id'],statuses={},errors={'conversion':pair.get('error','unavailable')},context_gaps=[]),[]
    for oracle in CHECKERS:
        mode='directory' if pair.get('matching_profile') == 'legacy_aidev' else 'file'
        scanned={}; failures=[]
        for side in ['before','after']:
            key=oracle+'_'+side
            try:
                scanned[side]=check(pair[side+'_yaml'],dict(path=pair[side+'_path'],oracle=oracle,collection_mode=mode)) if pair[side+'_exists'] else []
                statuses[key]='analyzed'; side_counts[key]=len(scanned[side])
            except Exception as exc:
                statuses[key]='error'; side_counts[key]=None; failures.append(side+': '+str(exc))
        if failures:
            statuses[oracle]='error'; errors[oracle]='; '.join(failures)
            # Observed findings have no delta label when the opposite scan failed.
            partial.extend(dict(side=side,**asdict(f)) for side,values in scanned.items() for f in values)
            continue
        try:
            rows.extend(compare_findings(scanned['before'],scanned['after'],pair)); statuses[oracle]='analyzed'
        except Exception as exc:
            statuses[oracle]='error'; errors[oracle]='matching: '+str(exc)
            partial.extend(dict(side=side,**asdict(f)) for side,values in scanned.items() for f in values)
    try:
        flags,gaps=change_flags(pair['before_yaml'],pair['after_yaml'],pair)
        rows.extend(dict(pair_id=pair['pair_id'],status='introduced',match_basis='change_predicate',needs_review=True,before_evidence=None,**asdict(f)) for f in flags)
        statuses['change']='analyzed'
    except Exception as exc: statuses['change']='error'; errors['change']=str(exc)
    return dict(pair_id=pair['pair_id'],statuses=statuses,errors=errors,context_gaps=gaps,
        side_scan_counts=side_counts,partial_findings=partial),rows
