"""Refresh group metadata/counts without rerunning unchanged tool diagnostics."""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq

ROOT=Path(__file__).resolve().parent
GROUPS=['privilege','credentials','execution_integrity','supply_chain','workflow_hygiene','workflow_correctness','ci_integrity']

def main():
 parser=argparse.ArgumentParser(); parser.add_argument('run'); args=parser.parse_args()
 from paths import OUT
 folder=Path(args.run); catalog_path=OUT/'rule_catalog.csv'
 with catalog_path.open(encoding='utf-8',newline='') as file: catalog={r['rule_id']:r for r in csv.DictReader(file)}
 findings=pq.read_table(folder/'findings.parquet').to_pylist()
 summaries=pq.read_table(folder/'pairs_summary.parquet').to_pylist()
 counts=collections.defaultdict(collections.Counter)
 for row in findings:
  row['rule_group']=catalog[row['rule_id']]['rule_group']
  counts[row['pair_id']][(row['rule_group'],row['status'])]+=1
 for row in summaries:
  counter=counts[row['pair_id']]
  complete=row.get('all_oracles_complete',False)
  gaps=json.loads(row.get('context_gaps','[]'))
  row['observed_group_counts']=json.dumps({g+':'+status:n for (g,status),n in counter.items()})
  row['all_checks_decidable']=complete and not gaps
  for group in GROUPS:
   for status in ['introduced','fixed','persisted']:
    row[group+'_'+status]=counter[(group,status)] if complete and not (group=='privilege' and gaps) else None
 pq.write_table(pa.Table.from_pylist(findings),folder/'findings.parquet')
 pq.write_table(pa.Table.from_pylist(summaries),folder/'pairs_summary.parquet')
 reviews=[r for r in findings if r['match_basis']=='unmatched' or r['needs_review']]
 pq.write_table(pa.Table.from_pylist(reviews),folder/'unmatched_findings.parquet')
 (folder/'grouping_metadata.json').write_text(json.dumps(dict(catalog_sha256=hashlib.sha256(catalog_path.read_bytes()).hexdigest(),findings=len(findings),summaries=len(summaries),method='Only group metadata/counts refreshed; tool diagnostics and statuses unchanged'),indent=2),encoding='utf-8')
 print('Refreshed rule groups:',folder)

if __name__=='__main__': main()
