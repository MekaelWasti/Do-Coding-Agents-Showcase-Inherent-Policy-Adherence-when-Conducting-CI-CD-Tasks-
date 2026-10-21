"""Retain the pinned full PR commit set, not only workflow-touching commits."""
import json
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from stream_aidev import OUT, remote_table, save_json

def main():
    prs=pq.read_table(OUT/'workflow_prs.parquet',columns=['id'])['id']
    rows=[]
    count=0
    with remote_table('pr_commits') as file:
        parquet=pq.ParquetFile(file)
        for batch in parquet.iter_batches(batch_size=8192,columns=['pr_id','sha']):
            table=pa.Table.from_batches([batch]); count+=len(table)
            rows.extend(table.filter(pc.is_in(table['pr_id'],value_set=prs)).to_pylist())
    pq.write_table(pa.Table.from_pylist(rows),OUT/'workflow_pr_commits.parquet')
    save_json(OUT/'commit_filter_counts.json',dict(source_commit_rows=count,selected_commit_rows=len(rows),selected_prs=len({r['pr_id'] for r in rows})))
    print((OUT/'commit_filter_counts.json').read_text())

if __name__=='__main__': main()
