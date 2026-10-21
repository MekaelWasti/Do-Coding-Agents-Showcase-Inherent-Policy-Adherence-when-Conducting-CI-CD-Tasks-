"""Audit comparison metadata and restore omitted workflow path transitions."""
import collections
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
import pyarrow.parquet as pq
from public_diff import fetch,parse_diff,CACHE as PUBLIC_CACHE
from recover_pairs import recover,RESULTS,CACHE,workflow_path
from stream_aidev import OUT,save_json


def workflow_metadata(files):
    return {r['filename']:(r['status'],r.get('previous_filename')) for r in files
            if r['filename'].startswith('.github/workflows/') and r['filename'].lower().endswith(('.yml','.yaml'))}

def missing_rename_pair(record,files,source_paths):
    present={row['path'] for row in record['pairs']}
    for meta in files:
        old=meta.get('previous_filename','')
        if meta.get('status')!='renamed' or not ({old,meta['filename']} & source_paths):continue
        target=meta['filename'] if workflow_path(meta['filename']) else old
        if workflow_path(target) and target not in present:return True
    return False


def main():
    paths=collections.defaultdict(set)
    for batch in pq.ParquetFile(OUT/'workflow_commit_files.parquet').iter_batches(batch_size=8192,columns=['pr_id','filename']):
        for row in batch.to_pylist():paths[row['pr_id']].add(row['filename'])
    targets=[]
    for path in RESULTS.glob('*.json'):
        record=json.loads(path.read_text(encoding='utf-8'))
        if record['status']!='recovered':continue
        if record.get('comparison_source')=='GitHub_public_comparison_diff':
            url=f"https://github.com/{record['repo']}/compare/{record['base_sha']}...{record['head_sha']}.diff"
            cached=PUBLIC_CACHE/(hashlib.sha256(url.encode()).hexdigest()+'.json')
            comparison=json.loads(cached.read_text(encoding='utf-8'))
            previous=workflow_metadata(comparison['files'])
            corrected_files=parse_diff(comparison['text']) if comparison['text'] else []
            restore=missing_rename_pair(record,corrected_files,paths[record['pr_id']])
            if previous!=workflow_metadata(corrected_files) or restore:
                target={key:record[key] for key in ['pr_id','repo','base_sha','head_sha']}
                target['restore_rename_pairs']=restore
                targets.append((target,previous))
            continue
        endpoint=f"repos/{record['repo']}/compare/{record['base_sha']}...{record['head_sha']}"
        cached=CACHE/(hashlib.sha256(endpoint.encode()).hexdigest()+'.json')
        if not cached.exists():continue
        comparison=json.loads(cached.read_text(encoding='utf-8'))
        if comparison['status']=='ok':
            files=comparison['response'][0].get('files',[])
            restore=missing_rename_pair(record,files,paths[record['pr_id']])
            if len(files)>=300 or restore:
                target={key:record[key] for key in ['pr_id','repo','base_sha','head_sha']}
                target['restore_rename_pairs']=restore
                targets.append((target,workflow_metadata(files)))
    prs={r['id']:r for r in pq.read_table(OUT/'workflow_prs.parquet').to_pylist()}
    ids={r['pr_id'] for r,files in targets}
    commits=collections.defaultdict(set)
    for batch in pq.ParquetFile(OUT/'workflow_pr_commits.parquet').iter_batches(batch_size=8192):
        for row in batch.to_pylist():
            if row['pr_id'] in ids:commits[row['pr_id']].add(row['sha'])
    def check(item):
        record,previous=item
        response=fetch(record['repo'],record['base_sha'],record['head_sha'])
        result=dict(pr_id=record['pr_id'],repo=record['repo'],base_sha=record['base_sha'],head_sha=record['head_sha'],status=response['status'])
        if response['status']!='ok':
            result.update(error=response.get('error'),workflow_metadata_equal=None)
        else:
            equal=previous==workflow_metadata(response['files'])
            result.update(api_workflow_files=len(previous),diff_files=len(response['files']),workflow_metadata_equal=equal,
                public_diff_sha256=response['sha256'],recovered_again=False)
            if not equal or record.get('restore_rename_pairs'):
                repaired=recover(prs[record['pr_id']],commits[record['pr_id']],paths[record['pr_id']],force=True)
                result.update(recovered_again=True,recovery_status=repaired['status'],restored_rename_pairs=record.get('restore_rename_pairs',False))
        return result
    results=[]
    with ThreadPoolExecutor(max_workers=2) as pool:
        for offset in range(0,len(targets),2):
            for result in pool.map(check,targets[offset:offset+2]):
                results.append(result)
                save_json(OUT/'comparison_audit.json',dict(targeted_prs=len(targets),checked=len(results),results=results))
                print(f"Capped comparison audit {len(results)}/{len(targets)}: {result['status']}",flush=True)
    save_json(OUT/'comparison_audit.json',dict(targeted_prs=len(targets),checked=len(results),results=results,
        repaired=sum(r.get('recovered_again',False) for r in results),unresolved=sum(r['status']!='ok' for r in results)))


if __name__=='__main__':main()
