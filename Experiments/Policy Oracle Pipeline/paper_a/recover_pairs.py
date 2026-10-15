"""Recover every selected PR at immutable first-parent base/frozen head.

Resumable per-PR results/cache. Ambiguous or unavailable history is retained
as an explicit exclusion, never replaced by a contemporary branch tip.
GitHub primary rate limits pause the live job until reset.
"""
import collections
import base64
import difflib
import hashlib
import json
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor,wait,FIRST_COMPLETED
from pathlib import Path
from urllib.error import HTTPError,URLError
from urllib.parse import quote
import requests
import pyarrow as pa
import pyarrow.parquet as pq
from stream_aidev import OUT,REVISION,save_json
from prefetch_parents import parent_path,PARENTS
from public_diff import fetch as public_comparison

CACHE=OUT/'github_cache'
RESULTS=OUT/'recovered_prs'
RATE_LOCK=threading.Lock()
RATE_UNTIL=0
RAW_SESSIONS=threading.local()

def raw_bytes(url):
    """Reuse one HTTP connection pool per worker; retain urllib error semantics."""
    if not hasattr(RAW_SESSIONS,'session'):
        RAW_SESSIONS.session=requests.Session()
        RAW_SESSIONS.session.headers.update({'User-Agent':'paper-a-research','Accept-Encoding':'identity'})
    try:
        with RAW_SESSIONS.session.get(url,timeout=60) as response:
            if response.status_code>=400:
                raise HTTPError(url,response.status_code,response.reason,response.headers,None)
            return response.content
    except requests.RequestException as exc:
        raise URLError(str(exc)) from exc

def gh(endpoint):
    global RATE_UNTIL
    path=CACHE/(hashlib.sha256(endpoint.encode()).hexdigest()+'.json')
    if path.exists():
        try:
            cached=json.loads(path.read_text(encoding='utf-8'))
            if cached['status'] in ['ok','not_found']: return cached
        except (OSError,ValueError): pass
    for attempt in range(5):
        while time.time()<RATE_UNTIL:
            time.sleep(max(.1,min(10,RATE_UNTIL-time.time())))
        try:
            run=subprocess.run(['gh','api','--paginate','--slurp',endpoint],capture_output=True,timeout=180)
        except (OSError,subprocess.TimeoutExpired) as exc:
            run=subprocess.CompletedProcess([],1,b'',str(exc).encode())
        stdout=run.stdout.decode('utf-8','replace'); stderr=run.stderr.decode('utf-8','replace')
        try: data=json.loads(stdout)
        except ValueError: data=None
        result=dict(endpoint=endpoint,status='ok' if run.returncode==0 and data is not None else 'not_found' if 'HTTP 404' in stderr else 'error',returncode=run.returncode,response=data,error=stderr)
        save_json(path,result)
        if result['status']!='error': return result
        if 'rate limit' in stderr.lower() or 'HTTP 429' in stderr:
            with RATE_LOCK:
                rate=subprocess.run(['gh','api','rate_limit'],capture_output=True,text=True,timeout=45)
                try: reset=json.loads(rate.stdout)['resources']['core']['reset']
                except (ValueError,KeyError): reset=time.time()+60
                RATE_UNTIL=max(RATE_UNTIL,reset+2)
            print(f'Rate-limited; live job waiting until UTC {time.strftime("%H:%M:%S",time.gmtime(RATE_UNTIL))}',flush=True)
        elif attempt<4: time.sleep(2**attempt)
    return result

def raw(repo,sha,path,absence_known=False):
    url=f'https://raw.githubusercontent.com/{repo}/{sha}/{quote(path,safe="/")}'
    cache=CACHE/(hashlib.sha256(url.encode()).hexdigest()+'.json')
    if cache.exists():
        try:
            cached=json.loads(cache.read_text(encoding='utf-8'))
            if cached['status']=='found': return cached
            if cached['status']=='absent' and (cached.get('absence_verified') or absence_known):
                if absence_known and not cached.get('absence_verified'):
                    cached.update(absence_verified=True,method='GitHub_compare_absence')
                    save_json(cache,cached)
                return cached
        except (OSError,ValueError): pass
    for attempt in range(4):
        try:
            body=raw_bytes(url)
            result=dict(url=url,status='found',text=body.decode('utf-8'),sha256=hashlib.sha256(body).hexdigest())
            break
        except HTTPError as exc:
            result=dict(url=url,status='absent' if exc.code==404 else 'error',error=str(exc),text=None)
            if exc.code==404:
                if absence_known:
                    result.update(absence_verified=True,method='GitHub_compare_absence')
                    break
                # Public raw URLs can return 404 for a now-private repository.
                # Authenticated contents distinguish that from actual absence.
                authenticated=gh(f'repos/{repo}/contents/{quote(path,safe="/")}?ref={sha}')
                if authenticated['status']=='ok':
                    payload=authenticated['response'][0]
                    if payload.get('type')=='file' and payload.get('encoding')=='base64':
                        body=base64.b64decode(payload['content'])
                        result=dict(url=url,status='found',text=body.decode('utf-8'),sha256=hashlib.sha256(body).hexdigest(),method='authenticated_contents_fallback')
                    else: result=dict(url=url,status='error',text=None,error='Unsupported authenticated contents response')
                elif authenticated['status']=='not_found':
                    commit=gh(f'repos/{repo}/git/commits/{sha}')
                    if commit['status']!='ok': result=dict(url=url,status='error',text=None,error='Cannot establish file absence: commit inaccessible')
                    else: result['absence_verified']=True
                else: result=dict(url=url,status='error',text=None,error='Authenticated file lookup failed')
                break
        except (URLError,UnicodeError,TimeoutError) as exc:
            result=dict(url=url,status='error',error=str(exc),text=None)
        if attempt<3: time.sleep(2**attempt)
    save_json(cache,result)
    return result

def commit_boundaries(frozen,by_sha):
    if not frozen or frozen-set(by_sha):
        raise ValueError('Pinned commit set empty or not fully recoverable')
    parents={sha:[p['sha'] for p in by_sha[sha]['parents']] for sha in frozen}
    first=[sha for sha in frozen if not any(p in frozen for p in parents[sha])]
    referenced={p for values in parents.values() for p in values if p in frozen}
    heads=sorted(frozen-referenced)
    if len(first)!=1 or len(heads)!=1 or not parents[first[0]]:
        raise ValueError('Ambiguous PR commit graph or parentless first commit')
    return parents[first[0]][0],heads[0],first[0]

def workflow_path(path):
    return path.startswith('.github/workflows/') and path.lower().endswith(('.yml','.yaml'))

def canonical_paths(files,compare_files):
    """A renamed workflow is one pair, independent of lexical path ordering."""
    candidates=set(files)
    for row in compare_files:
        old=row.get('previous_filename','')
        if row.get('status')=='renamed' and (row['filename'] in files or old in files):
            if workflow_path(row['filename']): candidates.add(row['filename'])
            elif workflow_path(old): candidates.add(old)  # Old workflow path may now be absent.
    old_to_new={r['previous_filename']:r['filename'] for r in compare_files
                if r.get('status')=='renamed' and r.get('previous_filename')}
    after_paths={row['filename'] for row in compare_files if row.get('status')!='removed'}
    return sorted(p for p in candidates if p not in old_to_new or old_to_new[p] not in candidates
                  or not workflow_path(old_to_new[p]) or p in after_paths)

def recover(pr,commits,files,force=False):
    path=RESULTS/f"{pr['id']}.json"
    if path.exists() and not force:
        try:
            cached=json.loads(path.read_text(encoding='utf-8'))
            if cached.get('recovery_revision')==2: return dict(cached,_checkpoint_reused=True)
        except ValueError: pass  # Resume an interrupted legacy non-atomic write.
    result=dict(pr_id=pr['id'],repo=pr['repo'],status='excluded',reason='',pairs=[],recovery_revision=2)
    frozen=set(commits)
    by_sha={}; prefetched=[]
    for sha in frozen:
        try:
            metadata=json.loads(parent_path(pr['repo'],sha).read_text(encoding='utf-8'))
            if metadata.get('complete') and metadata.get('repo')==pr['repo'] and metadata.get('sha')==sha:
                by_sha[sha]=dict(sha=sha,parents=metadata['parents']); prefetched.append(sha)
        except (OSError,ValueError,KeyError): pass
    if frozen-set(by_sha):
        response=gh(f"repos/{pr['repo']}/pulls/{pr['number']}/commits?per_page=100")
        live=[row for page in response['response'] for row in page] if response['status']=='ok' else []
        by_sha.update({row['sha']:row for row in live})
    result['commits_from_prefetch']=prefetched
    recovered_direct=[]
    for sha in sorted(frozen-set(by_sha)):
        direct=gh(f"repos/{pr['repo']}/commits/{sha}")
        if direct['status']=='ok' and direct['response'][0].get('sha')==sha:
            by_sha[sha]=direct['response'][0]; recovered_direct.append(sha)
    result['commits_recovered_directly']=recovered_direct
    try: base,head,first=commit_boundaries(frozen,by_sha)
    except ValueError as exc:
        result['reason']=str(exc); result['missing_commits']=sorted(frozen-set(by_sha))
        save_json(path,result); return result
    result.update(base_sha=base,head_sha=head,base_sha_method='first_parent_of_unique_first_pinned_PR_commit',first_pr_commit=first,status='recovered')
    # An authenticated compare supplies rename metadata/patches where available.
    endpoint=f"repos/{pr['repo']}/compare/{base}...{head}"
    comparison_path=CACHE/(hashlib.sha256(endpoint.encode()).hexdigest()+'.json')
    comparison=None
    try:
        cached=json.loads(comparison_path.read_text(encoding='utf-8'))
        if cached['status']=='ok' and len(cached['response'][0].get('files',[]))<300:
            comparison=cached
    except (OSError,ValueError,KeyError): pass
    compare_files=[]
    if comparison is None:
        public=public_comparison(pr['repo'],base,head)
        if public['status']=='ok':
            compare_files=public['files']; result['comparison_source']=public['source']
            result['comparison_url']=public['url']; result['comparison_sha256']=public['sha256']
        else:
            comparison=gh(endpoint); result['public_comparison_error']=public.get('error')
    if comparison is not None:
        result['comparison_source']='GitHub_REST_compare'
        if comparison['status']=='ok': compare_files=comparison['response'][0].get('files',[])
    result['comparison_file_count']=len(compare_files)
    result['comparison_may_be_truncated']=result['comparison_source']=='GitHub_REST_compare' and len(compare_files)>=300
    aliases={x['filename']:x for x in compare_files}
    for meta in compare_files:
        old=meta.get('previous_filename','')
        if meta.get('status')=='renamed' and workflow_path(old) and not workflow_path(meta['filename']):
            aliases.setdefault(old,dict(filename=old,status='removed'))
    candidates=canonical_paths(files,compare_files)
    for filename in candidates:
        if not workflow_path(filename): continue
        meta=aliases.get(filename,{})
        before=meta.get('previous_filename',filename)
        old=raw(pr['repo'],base,before,absence_known=meta.get('status')=='added')
        new=raw(pr['repo'],head,filename,absence_known=meta.get('status')=='removed')
        row=dict(pair_id=f"aidev_v5:{pr['repo']}:{pr['id']}:{filename}",source='aidev_v5',source_revision=REVISION,
            repo=pr['repo'],commit_or_pr=str(pr['id']),pr_number=pr['number'],agent_name=pr['agent'],author_class='agent',
            stars=pr['stars'],state=pr['state'],created_at=pr['created_at'],closed_at=pr['closed_at'],merged_at=pr['merged_at'],
            path=filename,before_path=before,after_path=filename,base_sha=base,head_sha=head,base_sha_method=result['base_sha_method'],
            before_exists=old['status']=='found' if old['status']!='error' else None,
            after_exists=new['status']=='found' if new['status']!='error' else None,
            before_yaml=old.get('text') if old['status']!='absent' else '',after_yaml=new.get('text') if new['status']!='absent' else '',
            conversion_status='ready',error='',prompt=None,prompt_candidates=[],link_quality='none',attribution_scope='pr',pilot=None)
        if 'error' in [old['status'],new['status']]: row.update(conversion_status='excluded',error='Immutable file retrieval failed')
        elif old.get('text')==new.get('text') and before==filename: continue
        row['change_type']='added' if old['status']=='absent' else 'deleted' if new['status']=='absent' else 'renamed' if before!=filename else 'modified'
        row['github_patch']=meta.get('patch')
        row['patch_recovery_method']=result['comparison_source'] if meta.get('patch') else 'full_immutable_GitHub_contents'
        if row['conversion_status']=='ready':
            row['complete_patch']=''.join(difflib.unified_diff(row['before_yaml'].splitlines(True),row['after_yaml'].splitlines(True),fromfile='a/'+before,tofile='b/'+filename))
        result['pairs'].append(row)
    result['net_unchanged_or_non_yaml_candidates']=len(candidates)-len(result['pairs'])
    save_json(path,result)
    return result

def export():
    # Keep immutable YAML on disk; do not retain every recovered PR in RAM.
    strings=['pair_id','source','source_revision','repo','commit_or_pr','agent_name','author_class',
        'state','created_at','closed_at','merged_at','path','before_path','after_path','base_sha','head_sha',
        'base_sha_method','before_yaml','after_yaml','conversion_status','error','prompt','link_quality',
        'attribution_scope','pilot','change_type','github_patch','patch_recovery_method','complete_patch']
    schema=pa.schema([(name,pa.string()) for name in strings]
        +[(name,pa.int64()) for name in ['pr_number','stars']]
        +[(name,pa.bool_()) for name in ['before_exists','after_exists']]
        +[('prompt_candidates',pa.list_(pa.string()))])
    pending=[]; unreadable=[]; statuses=collections.Counter(); reasons=collections.Counter(); revisions=collections.Counter()
    processed=0; total_pairs=0; usable=0
    temporary=OUT/'aidev_pairs.partial.parquet'
    writer=pq.ParquetWriter(temporary,schema)
    for path in sorted(RESULTS.glob('*.json')):
        try: result=json.loads(path.read_text(encoding='utf-8'))
        except (OSError,ValueError): unreadable.append(path.name); continue
        processed+=1; statuses[result['status']]+=1; revisions[result.get('recovery_revision',1)]+=1
        if result['status']=='excluded': reasons[result['reason']]+=1
        total_pairs+=len(result['pairs']); usable+=sum(r['conversion_status']=='ready' for r in result['pairs'])
        pending.extend(result['pairs'])
        if len(pending)>=256:
            writer.write_table(pa.Table.from_pylist(pending,schema=schema)); pending=[]
    if pending: writer.write_table(pa.Table.from_pylist(pending,schema=schema))
    writer.close(); temporary.replace(OUT/'aidev_pairs.parquet')
    save_json(OUT/'recovery_counts.json',dict(prs_processed=processed,statuses=dict(statuses),
        workflow_pairs=total_pairs,usable_pairs=usable,exclusion_reasons=dict(reasons),
        unreadable_checkpoints=unreadable,recovery_revisions=dict(revisions)))

def main():
    CACHE.mkdir(parents=True,exist_ok=True); RESULTS.mkdir(parents=True,exist_ok=True)
    prs=pq.read_table(OUT/'workflow_prs.parquet').to_pylist()
    commits=collections.defaultdict(set); files=collections.defaultdict(set)
    for row in pq.read_table(OUT/'workflow_pr_commits.parquet').to_pylist(): commits[row['pr_id']].add(row['sha'])
    for row in pq.read_table(OUT/'workflow_commit_files.parquet').to_pylist(): files[row['pr_id']].add(row['filename'])
    available_parents={path.name for path in PARENTS.glob('*.json')}
    completed={int(path.stem) for path in RESULTS.glob('*.json')}
    def priority(pr):
        if pr['id'] in completed: return (0,pr['id'])
        ready=all(parent_path(pr['repo'],sha).name in available_parents for sha in commits[pr['id']])
        return (1 if ready else 2,pr['id'])
    with ThreadPoolExecutor(max_workers=4) as pool:
        remaining=iter(sorted(prs,key=priority)); active=set(); index=0
        def submit_next():
            pr=next(remaining,None)
            if pr is not None: active.add(pool.submit(recover,pr,commits[pr['id']],files[pr['id']]))
        for _ in range(4): submit_next()
        while active:
            done,_=wait(active,return_when=FIRST_COMPLETED)
            for future in done:
                active.remove(future); result=future.result(); index+=1
                if index%25==0:
                    save_json(OUT/'recovery_progress.json',dict(processed_in_current_pass=index,total_prs=len(prs),recovery_revision=2,last_pr_id=result['pr_id']))
                    print(f"Processed {index}/{len(prs)} PRs; last status {result['status']}",flush=True)
                submit_next()
    # Per-PR JSON is already an atomic checkpoint. Rewriting the full growing
    # dataset every 250 new PRs repeats tens of GB of parsing and serialization.
    # Publish once, after every selected PR has been attempted.
    export()

if __name__=='__main__': main()
