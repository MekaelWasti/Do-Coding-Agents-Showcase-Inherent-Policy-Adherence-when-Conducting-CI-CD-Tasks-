"""Assemble the whole selected cohort, retaining pending/unrecoverable pairs."""
import collections
import json
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
from stream_aidev import OUT,REVISION,save_json

FIELDS=['pair_id','source','source_revision','repo','commit_or_pr','pr_number','agent_name','author_class','attribution_scope',
        'stars','state','created_at','closed_at','merged_at','path','before_path','after_path','base_sha','head_sha','base_sha_method',
        'before_exists','after_exists','before_yaml','after_yaml','change_type','conversion_status','error','prompt','prompt_candidates','link_quality','matching_profile',
        'snapshot_validation','metadata_error']
SCHEMA=pa.schema([(field,pa.int64() if field in ['pr_number','stars'] else
    pa.bool_() if field in ['before_exists','after_exists'] else
    pa.list_(pa.struct([(name,pa.string()) for name in ['session_id','prompt','agent_name']]))
    if field=='prompt_candidates' else pa.string()) for field in FIELDS])

def comparison_qualification(record, audited):
 key=(record['pr_id'],record.get('base_sha'),record.get('head_sha'))
 if record.get('comparison_may_be_truncated') and key not in audited:
  return 'REST comparison reached the 300-file limit; complete workflow rename metadata is not verified'
 return None

def main():
 prs=pq.read_table(OUT/'workflow_prs.parquet').to_pylist()
 audit_path=OUT/'comparison_audit.json'
 audit=json.loads(audit_path.read_text(encoding='utf-8')) if audit_path.exists() else {}
 audited={(r['pr_id'],r['base_sha'],r['head_sha']) for r in audit.get('results',[])
          if r['status']=='ok' and r.get('workflow_metadata_equal') is True}
 filenames=collections.defaultdict(set)
 for row in pq.read_table(OUT/'workflow_commit_files.parquet',columns=['pr_id','filename']).to_pylist():
  if row['filename'].lower().endswith(('.yml','.yaml')): filenames[row['pr_id']].add(row['filename'])
 buffer=[]; seen=set(); statuses=collections.Counter(); sources=collections.Counter(); qualifications=collections.Counter()
 pending=0; excluded=0; recovered=0
 temporary=OUT/'pairs.partial.parquet'
 writer=pq.ParquetWriter(temporary,SCHEMA)
 def emit(row):
  normalized={field:row.get(field) for field in FIELDS}
  if normalized['pair_id'] in seen: raise ValueError('Duplicate pair ID: '+normalized['pair_id'])
  seen.add(normalized['pair_id']); statuses[normalized['conversion_status']]+=1; sources[normalized['source']]+=1
  if normalized['metadata_error']: qualifications['metadata_qualified_pairs']+=1
  buffer.append(normalized)
  if len(buffer)>=256:
   writer.write_table(pa.Table.from_pylist(buffer,schema=SCHEMA)); buffer.clear()
 for pr in prs:
  record=OUT/'recovered_prs'/f"{pr['id']}.json"
  result=json.loads(record.read_text(encoding='utf-8')) if record.exists() else None
  if result and result['status']=='recovered':
   recovered+=1
   qualification=comparison_qualification(result,audited)
   for row in result['pairs']:
    emit(dict(row,metadata_error=qualification or row.get('metadata_error')))
  else:
   pending+=result is None; excluded+=result is not None
   for filename in sorted(filenames[pr['id']]):
    record=dict(pair_id=f"aidev_v5:{pr['repo']}:{pr['id']}:{filename}",source='aidev_v5',source_revision=REVISION,
      repo=pr['repo'],commit_or_pr=str(pr['id']),pr_number=pr['number'],agent_name=pr['agent'],author_class='agent',attribution_scope='pr',
      stars=pr['stars'],state=pr['state'],created_at=pr['created_at'],closed_at=pr['closed_at'],merged_at=pr['merged_at'],
      path=filename,before_path=filename,after_path=filename,base_sha_method='unavailable',
      conversion_status='pending' if result is None else 'excluded',error='Recovery pending' if result is None else result['reason'],
      prompt_candidates=[],link_quality='none',matching_profile='default')
    emit(record)
 swe_path=OUT/'swechat_verified_pairs.parquet'
 if swe_path.exists():
  for batch in pq.ParquetFile(swe_path).iter_batches(batch_size=256):
   for row in batch.to_pylist(): emit(row)
 if buffer: writer.write_table(pa.Table.from_pylist(buffer,schema=SCHEMA))
 writer.close(); temporary.replace(OUT/'pairs.parquet')
 save_json(OUT/'assembly_counts.json',dict(selected_prs=len(prs),recovered_prs=recovered,excluded_prs=excluded,pending_prs=pending,
   workflow_pairs=len(seen),statuses=dict(statuses),
   source_counts=dict(sources),metadata_qualified_pairs=qualifications['metadata_qualified_pairs'],full_recovery_processed=pending==0))
 print((OUT/'assembly_counts.json').read_text())

if __name__=='__main__': main()
