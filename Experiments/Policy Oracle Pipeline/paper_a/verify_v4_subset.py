"""Establish pilot agent membership and saved head membership in pinned AIDev v4."""
import json
from pathlib import Path
import fsspec
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from stream_aidev import OUT,save_json

REVISION='bc7996907b404359f581c43d5160afe6ed599a14'
def main():
 source=Path(__file__).resolve().parents[2]/'Data/AIDev/security_scan/agent_workflow_prs.json'
 entries=json.loads(source.read_text())
 wanted=pa.array([e['pr_id'] for e in entries],type=pa.int64())
 prs=[]; commits=[]
 fs=fsspec.filesystem('http',block_size=4*1024*1024)
 for name,columns,target in [('pull_request',['id','agent'],prs),('pr_commits',['pr_id','sha'],commits)]:
  url=f'https://huggingface.co/datasets/hao-li/AIDev/resolve/{REVISION}/{name}.parquet'
  with fs.open(url,'rb') as file:
   for batch in pq.ParquetFile(file).iter_batches(batch_size=8192,columns=columns):
    table=pa.Table.from_batches([batch]); key='id' if name=='pull_request' else 'pr_id'
    target.extend(table.filter(pc.is_in(table[key],value_set=wanted)).to_pylist())
 by_pr={p['id']:p for p in prs}; heads={(c['pr_id'],c['sha']) for c in commits}
 pq.write_table(pa.Table.from_pylist(prs),OUT/'v4_pr_subset.parquet')
 pq.write_table(pa.Table.from_pylist(commits),OUT/'v4_pr_commit_subset.parquet')
 result=dict(source='hao-li/AIDev',revision=REVISION,pilot_agent_prs=len(entries),matched_prs=len(by_pr),
  missing_pr_ids=[e['pr_id'] for e in entries if e['pr_id'] not in by_pr],
  agent_label_mismatches=[dict(pr_id=e['pr_id'],pilot=e['agent_name'],pinned=by_pr[e['pr_id']]['agent'])
   for e in entries if e['pr_id'] in by_pr and e['agent_name']!=by_pr[e['pr_id']]['agent']],
  saved_heads_in_pinned_commit_table=sum((e['pr_id'],e['head_sha']) in heads for e in entries),
  saved_heads_missing=[e['pr_id'] for e in entries if (e['pr_id'],e['head_sha']) not in heads],
  human_controls='Separate CI-run source; not asserted to be AIDev v4 agents')
 save_json(OUT/'v4_membership.json',result)
 print(json.dumps(result,indent=2))
 if result['missing_pr_ids'] or result['agent_label_mismatches']:
  raise SystemExit('Legacy PR cohort or attribution does not match pinned v4')

if __name__=='__main__': main()
