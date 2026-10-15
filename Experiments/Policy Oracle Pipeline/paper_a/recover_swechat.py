"""Attach actual first-parent SHAs and verify strict SWE-chat workflow snapshots."""
import collections
import json
from concurrent.futures import ThreadPoolExecutor
import pyarrow as pa
import pyarrow.parquet as pq
from recover_pairs import gh,raw,CACHE,canonical_paths
from stream_aidev import OUT,save_json

def process(key,rows):
 repo,head=key
 response=gh(f'repos/{repo}/commits/{head}')
 if response['status']!='ok':
  for row in rows:
   if row['conversion_status']=='ready' and row['before_yaml'] is not None and row['after_yaml'] is not None:
    # The dataset provides committed_version and an exactly reversible patch.
    # Remote disappearance does not erase that observed artifact evidence.
    row.update(base_sha=None,base_sha_method='dataset_reverse_patch_parent_sha_unavailable',
      snapshot_validation='dataset_patch_consistent_remote_unavailable',
      metadata_error='GitHub commit unavailable; actual parent SHA cannot be established')
   else: row.update(conversion_status='excluded',error='Commit unavailable; actual parent SHA cannot be established')
  return rows
 parents=response['response'][0].get('parents',[])
 if not parents:
  for row in rows: row.update(conversion_status='excluded',error='No first-parent commit')
  return rows
 base=parents[0]['sha']
 metadata={r['filename']:r for page in response['response'] for r in page.get('files',[])}
 canonical=set(canonical_paths([r['after_path'] for r in rows],metadata.values()))
 for row in rows:
  row.update(base_sha=base,base_sha_method='GitHub_commit_first_parent',head_sha=head,
    snapshot_validation='GitHub_verified',metadata_error='')
  original_ready=row['conversion_status']=='ready'
  if row['after_path'] not in canonical:
   row.update(conversion_status='excluded',error='Duplicate old path of workflow rename; canonical new-path pair retained')
   continue
  file_metadata=metadata.get(row['after_path'],{})
  if file_metadata.get('status')=='renamed' and file_metadata.get('previous_filename'):
   row['before_path']=file_metadata['previous_filename']
  retrieved={}
  for side,sha in [('before',base),('after',head)]:
   absent=(side=='before' and file_metadata.get('status')=='added') or (side=='after' and file_metadata.get('status')=='removed')
   fetched=raw(repo,sha,row[side+'_path'],absence_known=absent)
   retrieved[side]=fetched
   if fetched['status']=='error': row.update(conversion_status='excluded',error=side+' GitHub file verification failed')
   elif original_ready and (fetched['status']=='found')!=row[side+'_exists']:
    row.update(conversion_status='excluded',error=side+' existence disagrees with actual commit snapshot')
   elif original_ready and fetched['status']=='found' and fetched['text']!=row[side+'_yaml']:
    row.update(conversion_status='excluded',error=side+' content disagrees with actual commit snapshot')
  if not original_ready and all(x['status'] in ['found','absent'] for x in retrieved.values()):
   if retrieved['before'].get('text')==retrieved['after'].get('text'):
    row.update(conversion_status='excluded',error='No actual workflow content change at this commit')
   else:
    for side,value in retrieved.items():
     row[side+'_exists']=value['status']=='found'
     row[side+'_yaml']=value.get('text') if value['status']=='found' else ''
    row.update(conversion_status='ready',error='',change_type='added' if not row['before_exists'] else 'deleted' if not row['after_exists'] else 'renamed' if row['before_path']!=row['after_path'] else 'modified')
 return rows

def main():
 CACHE.mkdir(exist_ok=True)
 rows=pq.read_table(OUT/'swechat_pairs.parquet').to_pylist()
 groups=collections.defaultdict(list)
 for row in rows: groups[(row['repo'],row['head_sha'])].append(row)
 verified=[]
 with ThreadPoolExecutor(max_workers=4) as pool:
  for index,result in enumerate(pool.map(lambda item:process(*item),groups.items()),1):
   verified.extend(result)
   if index%20==0: print(f'SWE-chat parents verified {index}/{len(groups)}',flush=True)
 pq.write_table(pa.Table.from_pylist(verified),OUT/'swechat_verified_pairs.parquet')
 save_json(OUT/'swechat_recovery_counts.json',dict(prompt_linked_commits=len(groups),pairs=len(verified),
   statuses=dict(collections.Counter(r['conversion_status'] for r in verified)),
   actual_base_sha_available=sum(bool(r['base_sha']) for r in verified),
   metadata_errors=dict(collections.Counter(r.get('metadata_error','') for r in verified if r.get('metadata_error'))),
   errors=dict(collections.Counter(r['error'] for r in verified if r['conversion_status']!='ready'))))
 print((OUT/'swechat_recovery_counts.json').read_text())

if __name__=='__main__': main()
