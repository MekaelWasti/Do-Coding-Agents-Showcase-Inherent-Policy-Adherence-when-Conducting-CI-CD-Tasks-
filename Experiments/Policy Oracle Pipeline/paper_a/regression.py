"""Compare each legacy PR/commit's eligibility and introduced zizmor count."""
import collections
import csv
import json
from pathlib import Path
import pyarrow.parquet as pq

ROOT=Path(__file__).resolve().parent
from paths import OUT
DATA=ROOT.parents[2]/'Experiments/Data'

def read(path):
 with path.open(encoding='utf-8-sig',newline='') as f: return list(csv.DictReader(f))

def main():
 pairs=pq.read_table(OUT/'legacy_oracle_run/pairs_summary.parquet').to_pylist()
 groups=collections.defaultdict(list)
 for row in pairs: groups[(row['source'],row['repo'],row['commit_or_pr'])].append(row)
 expected=[]
 for row in read(DATA/'AIDev/security_scan/pr_findings.csv'):
  expected.append(dict(source='aidev' if row['label']=='agent' else 'ci_run',repo=row['repo'],change=row['pr_id'],
   usable=row['status']=='analyzed',introduced=int(row['introduced_count']) if row['status']=='analyzed' else None,label=row['label']))
 for row in read(DATA/'SWE-chat/workflow_zizmor_pilot/commit_results.csv'):
  expected.append(dict(source='swechat',repo=row['repo'],change=row['commit_sha'],usable=row['status']=='analyzed',
   introduced=int(row['new_finding_count']) if row['status']=='analyzed' else None,label=row['group']))
 differences=[]; counts=collections.defaultdict(lambda:dict(analyzed=0,positive=0,introduced_instances=0))
 for old in expected:
  rows=groups.get((old['source'],old['repo'],old['change']),[])
  usable=bool(rows) and all(r['zizmor_status']=='analyzed' for r in rows)
  introduced=sum(r['zizmor_introduced'] for r in rows) if usable else None
  if usable!=old['usable'] or (usable and introduced!=old['introduced']):
   differences.append(dict(old,actual_usable=usable,actual_introduced=introduced))
  if usable:
   summary=counts[old['source']+':'+old['label']]
   summary['analyzed']+=1; summary['positive']+=introduced>0; summary['introduced_instances']+=introduced
 result=dict(compared_changes=len(expected),differences=differences,summary=dict(counts),passed=not differences,
  scope='Legacy immutable snapshots; v4 membership verification is a separate required gate')
 (OUT/'regression.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
 print(json.dumps(result,indent=2))
 if differences: raise SystemExit('Pilot regression differences remain')

if __name__=='__main__': main()
