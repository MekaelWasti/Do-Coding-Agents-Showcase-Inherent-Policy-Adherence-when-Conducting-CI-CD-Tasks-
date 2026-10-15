"""Pinned zizmor adapter and pilot-compatible identity matching."""
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

ZIZMOR = str(Path(__file__).resolve().parent / "tools/zizmor.exe")
FLAGS = ["--offline", "--format", "json", "--min-severity", "low"]
EXCLUDED_RULES = {"self-repository", "archived-uses"}
version = subprocess.run([ZIZMOR, "--version"], capture_output=True, text=True, check=True).stdout.strip()
assert version == "zizmor 1.30.1"
# The full pipeline uses its pinned tool independently of the old pilot files.
# Check the historical manifest too when that optional source is available.
if (AIDEV / "scan_manifest.json").exists():
    assert version == read_json(AIDEV / "scan_manifest.json")["zizmor_version"]
print(version)

@dataclass
class Finding:
    oracle: str
    rule_id: str
    severity: str
    anchor: str
    detail: str
    job: str = ""
    step: str = ""
    evidence: str = ""
    line: int | None = None

def parsed_yaml(text):
    try:
        result = yaml.safe_load(text)
        return result if isinstance(result, dict) else {}
    except yaml.YAMLError:
        return {}

def job_steps(document, job):
    jobs = document.get("jobs", {})
    value = jobs.get(job, {}) if isinstance(jobs, dict) else {}
    return value.get("steps", []) if isinstance(value, dict) else []

def step_identity(document, job, index):
    if index is None:
        return ""
    steps = job_steps(document, job)
    if isinstance(steps, list) and index < len(steps) and isinstance(steps[index], dict):
        step = steps[index]
        for field in ("id", "name", "uses"):
            if step.get(field):
                value = str(step[field]).split("@", 1)[0] if field == "uses" else str(step[field])
                return f"{field}:{value}"
    return f"index:{index}"

@lru_cache(maxsize=512)
def scan_zizmor(yaml_text, path, collection_mode="file"):
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(yaml_text, encoding="utf-8", newline="")
        result = subprocess.run([ZIZMOR, *FLAGS, str(Path(directory) if collection_mode == "directory" else target)],
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
    if "failed to parse input" in result.stderr or "failed to validate" in result.stderr:
        raise ValueError(result.stderr.strip()[:500])
    try:
        raw = json.loads(result.stdout)
        if not isinstance(raw, list):
            raise ValueError("Expected a list of findings")
    except ValueError as exc:
        raise ValueError(f"zizmor scan failed: {result.stderr.strip()[:500]}") from exc

    document = parsed_yaml(yaml_text)
    findings = []
    for item in raw:
        if item.get("ignored") or item["ident"] in EXCLUDED_RULES:
            continue
        locations = item.get("locations", [])
        primary = next((x for x in locations if x["symbolic"].get("kind") == "Primary"), locations[0] if locations else None)
        if primary is None:
            raise ValueError("Finding has no location")
        route = primary["symbolic"].get("route", {}).get("route", [])
        job, index = "", None
        for i, part in enumerate(route[:-1]):
            if part.get("Key") == "jobs":
                job = route[i + 1].get("Key", "")
            if part.get("Key") == "steps":
                index = route[i + 1].get("Index")
        step = step_identity(document, job, index)
        anchor = f"jobs.{job}" if job else "workflow"
        if step:
            anchor += f".steps[{step}]"
        concrete = primary.get("concrete", {})
        line = concrete.get("location", {}).get("start_point", {}).get("row")
        findings.append(Finding(
            oracle="zizmor", rule_id=item["ident"],
            severity=item.get("determinations", {}).get("severity", ""),
            anchor=anchor, detail=item.get("desc", ""), job=job, step=step,
            evidence=str(concrete.get("feature", "")).replace("\n", " ")[:220],
            line=line + 1 if isinstance(line, int) else None,
        ))
    return findings

def run(yaml_text, context):
    if yaml_text is None:
        raise ValueError("Unavailable file content")
    return scan_zizmor(yaml_text, context["path"])

def compare_findings(before, after, pair):
    old, new = set(range(len(before))), set(range(len(after)))
    matches = []
    key = lambda f: (f.oracle, f.rule_id, f.anchor)
    old_counts, new_counts = Counter(map(key, before)), Counter(map(key, after))

    def match(i, j, basis, review=False):
        old.remove(i)
        new.remove(j)
        matches.append((i, j, basis, review))

    by_anchor = defaultdict(list)
    for i, finding in enumerate(before):
        by_anchor[key(finding)].append(i)
    for j, finding in enumerate(after):
        options = by_anchor[key(finding)]
        if options:
            i = options.pop()
            review = old_counts[key(finding)] > 1 or new_counts[key(finding)] > 1 or before[i].evidence != finding.evidence
            match(i, j, "anchor", review)

    by_evidence = defaultdict(list)
    evidence_key = lambda f: (f.oracle, f.rule_id, " ".join(f.evidence.split()))
    old_evidence_counts = Counter(evidence_key(before[i]) for i in old)
    new_evidence_counts = Counter(evidence_key(after[j]) for j in new)
    for i in sorted(old):
        finding = before[i]
        evidence = " ".join(finding.evidence.split())
        if evidence:
            by_evidence[evidence_key(finding)].append(i)
    for j in sorted(new):
        finding = after[j]
        identity = evidence_key(finding)
        options = by_evidence[identity]
        if options:
            review = old_evidence_counts[identity] > 1 or new_evidence_counts[identity] > 1
            match(options.pop(), j, "identical_evidence", review)

    before_doc = after_doc = None
    for j in sorted(new):
        finding = after[j]
        if not finding.job or finding.step:
            continue
        if pair.get("matching_profile") == "legacy_swechat":
            continue
        if before_doc is None:
            before_doc, after_doc = parsed_yaml(pair["before_yaml"]), parsed_yaml(pair["after_yaml"])
        steps = job_steps(after_doc, finding.job)
        if not steps:
            continue
        for i in sorted(old):
            previous = before[i]
            if previous.rule_id == finding.rule_id and previous.job and not previous.step:
                if job_steps(before_doc, previous.job) == steps:
                    match(i, j, "identical_job_steps", True)
                    break

    result = []
    for i, j, basis, review in matches:
        result.append(dict(pair_id=pair["pair_id"], status="persisted", match_basis=basis,
                           needs_review=review, before_evidence=before[i].evidence, **asdict(after[j])))
    for status, indexes, findings in [("introduced", sorted(new), after), ("fixed", sorted(old), before)]:
        for index in indexes:
            result.append(dict(pair_id=pair["pair_id"], status=status, match_basis="unmatched",
                               needs_review=bool(pair["before_exists"] and pair["after_exists"]),
                               before_evidence=findings[index].evidence if status == "fixed" else None,
                               **asdict(findings[index])))
    return result

def analyze_pair(pair):
    result = dict(pair_id=pair["pair_id"], scan_status="analyzed", error="",
                  introduced=0, fixed=0, persisted=0)
    if pair["conversion_status"] != "ready":
        result.update(scan_status="excluded", error=pair["error"], introduced=None, fixed=None, persisted=None)
        return result, []
    try:
        before = run(pair["before_yaml"], {"path": pair["before_path"]}) if pair["before_exists"] else []
        after = run(pair["after_yaml"], {"path": pair["after_path"]}) if pair["after_exists"] else []
        findings = compare_findings(before, after, pair)
        result.update(Counter(f["status"] for f in findings))
        return result, findings
    except Exception as exc:
        result.update(scan_status="excluded", error=str(exc), introduced=None, fixed=None, persisted=None)
        return result, []
