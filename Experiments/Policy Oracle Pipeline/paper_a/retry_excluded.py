"""Retry explicit history exclusions using the source-SHA fallback; raw data unchanged."""
import collections
import argparse
import json
from concurrent.futures import ThreadPoolExecutor,as_completed
import pyarrow.parquet as pq
from recover_pairs import recover,export,RESULTS
from stream_aidev import OUT,save_json

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--no-export',action='store_true',help='Leave shared exports to a currently running recovery worker')
    args=parser.parse_args()
    previous={}
    for path in RESULTS.glob('*.json'):
        try: row=json.loads(path.read_text(encoding='utf-8'))
        except ValueError: continue
        if row['status']=='excluded': previous[row['pr_id']]=row
    prs={r['id']:r for r in pq.read_table(OUT/'workflow_prs.parquet').to_pylist()}
    commits=collections.defaultdict(set); files=collections.defaultdict(set)
    for r in pq.read_table(OUT/'workflow_pr_commits.parquet').to_pylist():
        if r['pr_id'] in previous: commits[r['pr_id']].add(r['sha'])
    for r in pq.read_table(OUT/'workflow_commit_files.parquet').to_pylist():
        if r['pr_id'] in previous: files[r['pr_id']].add(r['filename'])
    outcomes=[]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures={pool.submit(recover,prs[k],commits[k],files[k],True):k for k in sorted(previous)}
        for future in as_completed(futures):
            row=future.result(); k=futures[future]
            outcomes.append(dict(pr_id=k,before_reason=previous[k]['reason'],after_status=row['status'],after_reason=row['reason']))
            save_json(OUT/'history_retry.json',outcomes)
            print(f"History retry {len(outcomes)}/{len(previous)}: {row['status']}",flush=True)
    if not args.no_export: export()

if __name__=='__main__': main()
