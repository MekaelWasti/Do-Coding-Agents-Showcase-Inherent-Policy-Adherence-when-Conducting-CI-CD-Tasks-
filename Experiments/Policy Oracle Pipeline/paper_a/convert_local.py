"""Local pilot and strict SWE-chat conversion extracted from the existing notebook."""

display = lambda *args, **kwargs: None
from pathlib import Path
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from functools import lru_cache
import json
import re
import shutil
import subprocess
import tempfile

import pandas as pd
import pyarrow.parquet as pq
import yaml

# Works when the notebook starts here or at the repository root.
ROOT = next(p for p in [Path.cwd(), *Path.cwd().parents] if (p / "Experiments/Data").exists())
DATA = ROOT / "Experiments/Data"
AIDEV = DATA / "AIDev/security_scan"
SWECHAT = DATA / "SWE-chat/data"

def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))

def workflow(path):
    return path.startswith(".github/workflows/") and path.lower().endswith((".yml", ".yaml"))

def pair_record(source, repo, change, path, author_class, pilot):
    return dict(
        pair_id=f"{source}:{repo}:{change}:{path}", source=source, pilot=pilot,
        repo=repo, commit_or_pr=str(change), path=path, author_class=author_class,
        attribution_scope=None, agent_name=None, change_type=None,
        before_path=path, after_path=path,
        before_exists=None, after_exists=None, before_yaml=None, after_yaml=None,
        prompt=None, prompt_candidates=[], link_quality="none",
        conversion_status="ready", error="",
    )

aidev_entries = read_json(AIDEV / "agent_workflow_prs.json") + read_json(AIDEV / "human_workflow_prs.json")
snapshots = {x["pr_id"]: x for x in read_json(AIDEV / "snapshot_manifest.json")}

def convert_aidev(entry):
    rows = []
    for file in snapshots[entry["pr_id"]]["files"]:
        old, new = file["before_path"], file["after_path"]
        path = new if workflow(new) else old
        source = "aidev" if entry["label"] == "agent" else "ci_run"
        row = pair_record(source, entry["repo"], entry["pr_id"], path, entry["label"], "aidev")
        row.update(
            attribution_scope="pr", agent_name=entry.get("agent_name"),
            change_type={"removed": "deleted"}.get(file["status"], file["status"]),
            before_path=old, after_path=new,
        )
        try:
            for side, prefix, filename in [("base", "before", old), ("head", "after", new)]:
                state = file[side]
                if state == "fetched":
                    row[f"{prefix}_yaml"] = (AIDEV / side / str(entry["pr_id"]) / filename).read_text(encoding="utf-8")
                    row[f"{prefix}_exists"] = True
                elif state == "expected_absent" and (
                    (prefix == "before" and row["change_type"] == "added") or
                    (prefix == "after" and row["change_type"] == "deleted")
                ):
                    row[f"{prefix}_yaml"] = ""
                    row[f"{prefix}_exists"] = False
                else:
                    raise ValueError(f"{prefix} snapshot unavailable: {state} ({file['status']})")
        except Exception as exc:
            row.update(conversion_status="excluded", error=str(exc))
        rows.append(row)
    return rows

aidev_rows = [row for entry in aidev_entries for row in convert_aidev(entry)]
pd.DataFrame(aidev_rows).groupby(["source", "conversion_status"]).size().rename("workflow_pairs")

swe_changes = {}
columns = ["repo_id", "commit_sha", "checkpoint_pk", "files_changed", "file_attribution", "patch"]
for batch in pq.ParquetFile(SWECHAT / "commits.parquet").iter_batches(batch_size=200, columns=columns):
    for record in batch.to_pylist():
        if ".github/workflows/" not in (record["files_changed"] or ""):
            continue
        attribution = json.loads(record["file_attribution"] or "{}")
        files = {p: v for p, v in attribution.items() if workflow(p) and isinstance(v, dict)}
        if not files:
            continue
        key = record["repo_id"], record["commit_sha"]
        change = swe_changes.setdefault(key, dict(files={}, checkpoints=set(), patch=record["patch"] or ""))
        change["files"].update(files)
        change["checkpoints"].add(record["checkpoint_pk"])

assert len(swe_changes) == 402
print(f"{len(swe_changes)} root-workflow commits in {len({repo for repo, sha in swe_changes})} repositories")

def reconstruct_workflow(path, file, patch):
    blocks = re.split(r"(?=^diff --git )", patch, flags=re.MULTILINE)
    block = next((b for b in blocks if b.startswith(f"diff --git a/{path} b/{path}\n")), None)
    if block is None:
        raise ValueError("No exact patch for this path (a rename may need separate handling)")
    kind = "added" if "\nnew file mode " in block else "deleted" if "\ndeleted file mode " in block else "modified"
    after_exists = kind != "deleted"
    after = file.get("committed_version") if after_exists else ""
    if after is None:
        raise ValueError("Committed file content is unavailable")
    with tempfile.TemporaryDirectory() as directory:
        folder = Path(directory)
        target = folder / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if after_exists:
            target.write_text(after, encoding="utf-8", newline="")
        result = subprocess.run(
            ["git", "apply", "--reverse", "--whitespace=nowarn", "-"],
            input=block.encode("utf-8"), cwd=folder, capture_output=True,
        )
        if result.returncode:
            raise ValueError(result.stderr.decode("utf-8", "replace").strip())
        before_exists = target.exists()
        if before_exists != (kind != "added"):
            raise ValueError("Patch and reconstructed file existence disagree")
        before = target.read_text(encoding="utf-8") if before_exists else ""
    return dict(change_type=kind, before_exists=before_exists, after_exists=after_exists,
                before_yaml=before, after_yaml=after)

swechat_rows = []
for (repo, sha), change in swe_changes.items():
    for path, file in change["files"].items():
        author = {"agent_only": "agent", "mixed": "mixed", "human_only": "human"}.get(file.get("attribution"), "unknown")
        row = pair_record("swechat", repo, sha, path, author, "swechat")
        row["attribution_scope"] = "file"
        try:
            row.update(reconstruct_workflow(path, file, change["patch"]))
        except Exception as exc:
            row.update(conversion_status="excluded", error=str(exc))
        swechat_rows.append(row)

pd.DataFrame(swechat_rows).groupby(["author_class", "conversion_status"]).size().rename("workflow_pairs")

sessions = pq.read_table(SWECHAT / "sessions.parquet").to_pylist()
session_by_id = {s["session_id"]: s for s in sessions}
sessions_by_checkpoint = defaultdict(list)
for session in sessions:
    checkpoints = set(json.loads(session["checkpoint_ids"] or "[]"))
    if session["canonical_checkpoint_pk"]:
        checkpoints.add(session["canonical_checkpoint_pk"])
    for checkpoint in checkpoints:
        sessions_by_checkpoint[(session["repo_id"], checkpoint)].append(session)

candidate_sessions = {}
for row in swechat_rows:
    ids = set()
    if row["author_class"] in ("agent", "mixed"):
        change = swe_changes[(row["repo"], row["commit_or_pr"])]
        for checkpoint in change["checkpoints"]:
            for session in sessions_by_checkpoint[(row["repo"], checkpoint)]:
                touched = {p.lower() for p in json.loads(session["files_touched"] or "[]")}
                if (session["prompt_count"] or 0) > 0 and row["path"].lower() in touched:
                    ids.add(session["session_id"])
    candidate_sessions[row["pair_id"]] = ids

wanted = set().union(*candidate_sessions.values())
first_prompts = {}
columns = ["session_id", "turn_type", "turn_number", "is_continuation", "content"]
for batch in pq.ParquetFile(SWECHAT / "conversations.parquet").iter_batches(batch_size=50000, columns=columns):
    for turn in batch.to_pylist():
        sid, text = turn["session_id"], turn["content"]
        if sid in wanted and turn["turn_type"] == "user_prompt" and not turn["is_continuation"] and text and text.strip():
            if sid not in first_prompts or turn["turn_number"] < first_prompts[sid][0]:
                first_prompts[sid] = (turn["turn_number"], text.strip())

for row in swechat_rows:
    ids = sorted(candidate_sessions[row["pair_id"]] & first_prompts.keys())
    row["prompt_candidates"] = [
        {"session_id": sid, "prompt": first_prompts[sid][1], "agent_name": session_by_id[sid]["agent"]}
        for sid in ids
    ]
    if ids:
        row["link_quality"] = "strict"
        row["prompt"] = first_prompts[ids[0]][1] if len(ids) == 1 else None
        agents = {session_by_id[sid]["agent"] for sid in ids}
        row["agent_name"] = next(iter(agents)) if len(agents) == 1 else None

strict_changes = {(r["repo"], r["commit_or_pr"]) for r in swechat_rows if r["link_quality"] == "strict"}
assert len(strict_changes) == 119
print(f"{len(strict_changes)} commits have at least one strictly linked agent-attributed workflow")

df_unified_table = pd.DataFrame(aidev_rows + swechat_rows)
assert df_unified_table.pair_id.is_unique

display(df_unified_table.groupby(["source", "author_class"]).agg(
    workflow_pairs=("pair_id", "size"),
    changes=("commit_or_pr", "nunique"),
))
display(df_unified_table[[
    "source", "repo", "commit_or_pr", "path", "author_class",
    "change_type", "before_exists", "after_exists", "link_quality", "conversion_status",
]].head(10))
# Inspect a full row with: df_unified_table.iloc[0]

from paths import OUT
OUT.mkdir(exist_ok=True)
entry_by_id = {str(e["pr_id"]): e for e in aidev_entries}
for row in aidev_rows:
    entry = entry_by_id[row["commit_or_pr"]]
    row.update(base_sha=entry["base_sha"], head_sha=entry["head_sha"], base_sha_method="legacy_pilot_cached_base", stars=None, state=None, created_at=None, matching_profile="legacy_aidev")
for row in swechat_rows:
    row.update(base_sha=None, head_sha=row["commit_or_pr"], base_sha_method="reverse_patch_parent_sha_pending", stars=None, state=None, created_at=None, matching_profile="legacy_swechat")
all_rows = aidev_rows + swechat_rows
pq.write_table(__import__("pyarrow").Table.from_pylist(all_rows), OUT / "legacy_pairs.parquet")
strict = [r for r in swechat_rows if r["link_quality"] == "strict"]
pq.write_table(__import__("pyarrow").Table.from_pylist([dict(r, matching_profile="default") for r in strict]), OUT / "swechat_pairs.parquet")
(OUT / "local_conversion_counts.json").write_text(json.dumps(dict(aidev_prs=len(aidev_entries), aidev_pairs=len(aidev_rows), swechat_commits=len(swe_changes), swechat_pairs=len(swechat_rows), strict_commits=len(strict_changes), strict_pairs=len(strict), errors=sum(r["conversion_status"]!="ready" for r in all_rows)), indent=2), encoding="utf-8")
print((OUT / "local_conversion_counts.json").read_text())
