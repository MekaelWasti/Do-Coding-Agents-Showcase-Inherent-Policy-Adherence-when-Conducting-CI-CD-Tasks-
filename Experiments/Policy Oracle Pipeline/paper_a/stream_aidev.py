"""Stream author-pinned AIDev-pop workflow records, then join light metadata.

The author's v5 release is hosted at AIDev-7.6M; AIDev@v5 is not a
published tag. That discrepancy is explicit in provenance, never hidden.
Only selected columns are read; raw source tables are not modified.
"""
import argparse
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import fsspec
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parent
from paths import OUT
SOURCE = "hao-li/AIDev-7.6M"
REVISION = "37bbe1533e26cc1e1374917dba1186d1c8a4dc81"


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    import os
    import threading
    import time
    temporary=path.with_suffix(f'.{os.getpid()}.{threading.get_ident()}.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    for attempt in range(50):
        try:
            temporary.replace(path)
            break
        except PermissionError:
            if attempt==49: raise
            time.sleep(.02)


def remote_table(name, columns=None):
    url = f"https://huggingface.co/datasets/{SOURCE}/resolve/{REVISION}/{name}.parquet"
    fs = fsspec.filesystem("http", block_size=4*1024*1024)
    return fs.open(url, "rb")


def resolve_provenance():
    evidence = dict(requested_source="hao-li/AIDev@v5", actual_source=SOURCE,
                    actual_revision=REVISION, interpretation="Official author's v5 WIP location; original v5 tag is unpublished")
    for key, url in {
        "requested_revision": "https://huggingface.co/api/datasets/hao-li/AIDev/revision/v5",
        "pinned_revision": f"https://huggingface.co/api/datasets/{SOURCE}/revision/{REVISION}",
        "original_refs": "https://huggingface.co/api/datasets/hao-li/AIDev/refs",
    }.items():
        try:
            with urlopen(Request(url, headers={"User-Agent":"paper-a-research"}), timeout=45) as response:
                evidence[key] = dict(status=response.status, response=json.load(response))
        except HTTPError as exc:
            evidence[key] = dict(status=exc.code, response=exc.read().decode("utf-8", "replace"))
    url = f"https://huggingface.co/datasets/{SOURCE}/raw/{REVISION}/README.md"
    with urlopen(url, timeout=45) as response:
        card = response.read()
    (OUT / "source_card.md").write_bytes(card)
    if evidence["pinned_revision"]["response"]["sha"] != REVISION:
        raise ValueError("Resolved source SHA differs from pin")
    save_json(OUT / "source_provenance.json", evidence)


def extract():
    target = OUT / "workflow_commit_files.parquet"
    counts = dict(commit_file_rows_read=0, under_workflow_directory=0,
                  yaml_workflow_rows=0, row_groups_completed=0)
    shards = OUT / "stream_shards"
    shards.mkdir(parents=True, exist_ok=True)
    with remote_table("pr_commit_details") as file:
        parquet = pq.ParquetFile(file)
        counts["source_rows"] = parquet.metadata.num_rows
        counts["source_row_groups"] = parquet.num_row_groups
        schema = pa.schema([("sha",pa.string()),("pr_id",pa.int64()),
                            ("filename",pa.string()),("status",pa.string())])
        for index in range(parquet.num_row_groups):
            shard, stats = shards / f"{index:03d}.parquet", shards / f"{index:03d}.json"
            if not (shard.exists() and stats.exists()):
                local = dict(commit_file_rows_read=0, under_workflow_directory=0, yaml_workflow_rows=0)
                with pq.ParquetWriter(shard, schema) as writer:
                    for batch in parquet.iter_batches(batch_size=8192, row_groups=[index], columns=schema.names):
                        table = pa.Table.from_batches([batch])
                        local["commit_file_rows_read"] += len(table)
                        paths = table["filename"]
                        mask = pc.fill_null(pc.starts_with(paths,".github/workflows/"),False)
                        selected = table.filter(mask)
                        local["under_workflow_directory"] += len(selected)
                        if len(selected):
                            local["yaml_workflow_rows"] += sum(str(p).lower().endswith((".yml",".yaml")) for p in selected["filename"].to_pylist())
                            writer.write_table(selected)
                save_json(stats, local)
            local = json.loads(stats.read_text())
            for key in local:
                counts[key] += local[key]
            counts["row_groups_completed"] += 1
            save_json(OUT/"filtering_counts.json",counts)
            print(f"row group {index+1}/{parquet.num_row_groups}: {counts}",flush=True)
        tables = [pq.read_table(shards/f"{i:03d}.parquet") for i in range(parquet.num_row_groups)]
        selected = pa.concat_tables(tables)
        pq.write_table(selected,target)
    counts["distinct_pr_ids"] = len(set(selected["pr_id"].to_pylist()))
    counts["distinct_commit_path_records"] = len(set(zip(*[selected[c].to_pylist() for c in ["pr_id","sha","filename"]])))
    save_json(OUT/"filtering_counts.json",counts)
    return selected, counts


def join_metadata(selected, counts):
    wanted = pa.array(sorted(set(selected["pr_id"].to_pylist())), type=pa.int64())
    records = []
    columns = ["id","number","agent","state","created_at","closed_at","merged_at","repo_id","repo_url","html_url"]
    with remote_table("pull_request") as file:
        parquet = pq.ParquetFile(file)
        counts["pull_request_source_rows"] = parquet.metadata.num_rows
        for batch in parquet.iter_batches(batch_size=8192,columns=columns):
            table = pa.Table.from_batches([batch])
            selected_prs = table.filter(pc.is_in(table["id"],value_set=wanted))
            records.extend(selected_prs.to_pylist())
    with remote_table("repository") as file:
        parquet = pq.ParquetFile(file)
        save_json(OUT/"repository_schema.json",dict(fields=parquet.schema_arrow.names))
        columns = [c for c in ["id","full_name","stars","html_url","url"] if c in parquet.schema_arrow.names]
        repos = pq.read_table(file,columns=columns).to_pylist()
    by_repo = {x["id"]:x for x in repos}
    by_pr = {x["id"]:x for x in records}
    if len(by_pr)!=len(records):
        raise ValueError("Duplicate PR metadata keys")
    rows = []
    for record in records:
        repo = by_repo.get(record["repo_id"])
        rows.append(dict(record, repo=(repo or {}).get("full_name"),
                         stars=(repo or {}).get("stars"), repo_join_status="matched" if repo else "missing"))
    pq.write_table(pa.Table.from_pylist(rows),OUT/"workflow_prs.parquet")
    counts.update(joined_prs=len(rows),missing_pr_metadata=len(set(wanted.to_pylist())-set(by_pr)),
                  missing_repository_metadata=sum(x["repo_join_status"]=="missing" for x in rows),
                  joined_repositories=len({x["repo"] for x in rows if x["repo"]}))
    save_json(OUT/"filtering_counts.json",counts)
    print(json.dumps(counts,indent=2),flush=True)


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    resolve_provenance()
    selected, counts = extract()
    join_metadata(selected,counts)


if __name__ == "__main__":
    main()
