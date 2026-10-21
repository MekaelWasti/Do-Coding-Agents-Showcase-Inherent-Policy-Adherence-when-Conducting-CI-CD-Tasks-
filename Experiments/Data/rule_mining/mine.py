"""Count literal workflow practices and candidate instruction statements.

Reads raw data; writes only beside this script. No scanner or LLM is used.
"""
import csv
import hashlib
import json
import math
import random
import re
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "_deps"))
from ruamel.yaml import YAML
import pyarrow
import pyarrow.parquet as pq

DATA = Path(r"E:\!My Files\CS\Grammar")
PILOT = ROOT.parent / "AIDev" / "security_scan"
SEED = 20261006
RULES = ["R1_permissions_declared", "R2_no_write_all", "R3_no_pr_target",
         "R4_no_workflow_run", "R5_no_untrusted_in_run", "R6_third_party_sha_pinned",
         "R7_all_actions_sha_pinned", "R8_checkout_no_persist_creds", "R9_job_timeouts",
         "R10_concurrency", "R11_no_continue_on_error"]

# Every listed group must match somewhere in the same statement.
# These retrieve mentions, not direction, authority, or confirmed obligations.
PATTERNS = {
    RULES[0]: [r"\bpermissions?\b", r"\b(declar\w*|explicit\w*|defin\w*|specif\w*|set|setting|block)\b"],
    RULES[1]: [r"\bwrite[-_ ]all\b"],
    RULES[2]: [r"\bpull_request_target\b"],
    RULES[3]: [r"\bworkflow_run\b"],
    RULES[4]: [r"\b(inject\w*|untrusted|github\s*\.\s*(event|head_ref))\b",
               r"\b(run|shell|script\w*|expression\w*|interpolat\w*|inject\w*)\b"],
    RULES[5]: [r"\b(pin(?:s|ned|ning)?|sha|commit[- ]hash\w*|immutable)\b",
               r"\b(third[- ]party|external)\b", r"\bactions?\b|\buses\s*:"],
    RULES[6]: [r"\b(pin(?:s|ned|ning)?|sha|commit[- ]hash\w*|immutable)\b", r"\bactions?\b|\buses\s*:"],
    RULES[7]: [r"\bpersist[-_ ]credentials\b|\bcheckout\b.*\b(credentials?|tokens?)\b"],
    RULES[8]: [r"\btimeout[-_ ]minutes\b|\btimeouts?\b"],
    RULES[9]: [r"\bconcurrency\b"],
    RULES[10]: [r"\bcontinue[-_ ]on[-_ ]error\b"],
}
CI_PATTERNS = [r"\bgithub\s+actions\b", r"\bworkflows?\b", r"\.github/workflows\b",
               r"\bci\b", r"\bpipelines?\b", r"\bpin(?:s|ned|ning)?\b", r"\bsha\b",
               r"\bpermissions?\b", r"\bpull_request_target\b", r"\bsecrets?\b",
               r"\btokens?\b", r"\bcontinue-on-error\b", r"\btimeouts?\b", r"\bconcurrency\b",
               r"\bworkflow_run\b", r"\bpersist-credentials\b"]
UNTRUSTED_PATHS = ["github.event.issue.title", "github.event.issue.body",
                   "github.event.pull_request.title", "github.event.pull_request.body",
                   "github.event.comment.body", "github.event.review.body",
                   "github.event.head_commit.message", "github.head_ref",
                   "github.event.pull_request.head.ref"]
UNTRUSTED_RE = re.compile(r"\b(?:" + "|".join(
    r"\s*\.\s*".join(map(re.escape, path.split("."))) for path in UNTRUSTED_PATHS) + r")\b", re.I)


def load_workflow(text):
    document = YAML(typ="rt").load(text)
    if not isinstance(document, dict):
        raise ValueError("Workflow root is not a mapping")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise ValueError("Workflow has no nonempty jobs mapping")
    if any(not isinstance(job, dict) for job in jobs.values()):
        raise ValueError("A job is not a mapping")
    return document


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def literal(value, wanted):
    return value is wanted or (isinstance(value, str) and value.lower() == str(wanted).lower())


def check_workflow(document):
    """Return {rule: (applicable, follows)} using the requested literal definitions."""
    jobs = list(document["jobs"].values())
    steps = [step for job in jobs for step in job.get("steps", []) if isinstance(step, dict)]
    uses = [str(item["uses"]) for item in jobs + steps if "uses" in item]
    actions = [ref for ref in uses if not ref.startswith(("./", "docker://"))]
    third_party = [ref for ref in actions if ref.split("/", 1)[0].lower() not in {"actions", "github"}]
    checkout = [step for step in steps if str(step.get("uses", "")).lower().startswith("actions/checkout@")]
    runs = [str(step["run"]) for step in steps if "run" in step]
    trigger = document.get("on", document.get(True))
    events = {trigger} if isinstance(trigger, str) else set(trigger) if isinstance(trigger, (dict, list)) else set()
    interpolations = [expr for run in runs for expr in re.findall(r"\$\{\{[\s\S]*?\}\}", run)]
    pinned = lambda refs: all(re.search(r"@[0-9a-fA-F]{40}$", ref) is not None for ref in refs)
    values = [
        (True, "permissions" in document or all("permissions" in job for job in jobs)),
        (True, not any(item.get("permissions") == "write-all" for item in walk(document))),
        (True, "pull_request_target" not in events),
        (True, "workflow_run" not in events),
        (bool(runs), not any(UNTRUSTED_RE.search(expr) for expr in interpolations)),
        (bool(third_party), pinned(third_party)),
        (bool(actions), pinned(actions)),
        (bool(checkout), all(isinstance(step.get("with"), dict) and
                             literal(step["with"].get("persist-credentials"), False) for step in checkout)),
        (True, all("timeout-minutes" in job for job in jobs)),
        (True, "concurrency" in document or all("concurrency" in job for job in jobs)),
        (True, not any(literal(item.get("continue-on-error"), True) for item in jobs + steps)),
    ]
    return dict(zip(RULES, values))


def statements(content):
    """Keep line provenance; split each nonempty line at sentence-ending punctuation."""
    for number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        # Don't split '.github', file extensions, or punctuation without whitespace.
        for statement in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9`])", line):
            yield number, statement.strip()


def match_statement(statement):
    if not any(re.search(pattern, statement, re.I) for pattern in CI_PATTERNS):
        return None
    matched = [rule for rule, patterns in PATTERNS.items()
               if all(re.search(pattern, statement, re.I) for pattern in patterns)]
    return matched or ["R_other_ci"]


def write_csv(name, rows, fields):
    with (ROOT / name).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percent(numerator, denominator):
    return 100 * numerator / denominator if denominator else None


def build_corpus():
    entries = json.loads((PILOT / "agent_workflow_prs.json").read_text(encoding="utf-8"))
    dates = json.loads((ROOT / "base_commit_dates.json").read_text(encoding="utf-8"))
    candidates, dropped = [], Counter({"touched_workflow_records": 0, "added_no_before": 0,
                                      "before_not_workflow": 0, "missing_before_snapshot": 0})
    for entry in entries:
        for file in entry["files"]:
            dropped["touched_workflow_records"] += 1
            path = file.get("previous_filename") if file["status"] == "renamed" else file["filename"]
            if file["status"] == "added":
                dropped["added_no_before"] += 1
                continue
            if not path or not path.startswith(".github/workflows/") or not path.lower().endswith((".yml", ".yaml")):
                dropped["before_not_workflow"] += 1
                continue
            local = PILOT / "base" / str(entry["pr_id"]) / path
            if not local.exists():
                dropped["missing_before_snapshot"] += 1
                continue
            key = f"{entry['repo']}@{entry['base_sha']}"
            candidates.append({"repo": entry["repo"], "workflow_path": path, "pr_id": entry["pr_id"],
                               "base_sha": entry["base_sha"], "base_commit_date": dates.get(key, {}).get("committer_date"),
                               "snapshot_path": str(local), "snapshot_sha256": sha256(local)})
    groups = defaultdict(list)
    for row in candidates:
        groups[(row["repo"], row["workflow_path"])].append(row)
    selected = []
    for key, group in sorted(groups.items()):
        if len({row["base_sha"] for row in group}) > 1 and any(not row["base_commit_date"] for row in group):
            raise ValueError(f"Missing competing base commit date for {key}; run prepare_metadata.py")
        winner = min(group, key=lambda row: (row["base_commit_date"] or "", row["base_sha"], row["pr_id"]))
        for row in group:
            row["selected"] = row is winner
            row["selection_basis"] = "earliest_base_committer_date" if len(group) > 1 else "only_available_before"
        selected.append(winner)
    fields = ["repo", "workflow_path", "pr_id", "base_sha", "base_commit_date", "snapshot_path", "snapshot_sha256",
              "selected", "selection_basis"]
    write_csv("corpus_candidates.csv", candidates, fields)
    write_csv("observed_corpus.csv", selected, fields)
    counts = {"input_agent_prs": len(entries), **dict(dropped), "before_candidates": len(candidates),
              "dedup_dropped": len(candidates) - len(selected), "dedup_files": len(selected),
              "dedup_repos": len({row["repo"] for row in selected})}
    if len(selected) < 50:
        (ROOT / "README.md").write_text(f"Stopped: fewer than 50 before-files after dedup.\n\n{counts}\n", encoding="utf-8")
        raise SystemExit("Fewer than 50 before-files after dedup; stopped as requested")
    return entries, selected, counts


def observed(entries, corpus, counts):
    # AIDev-pop membership check: select light columns and the 95 relevant IDs only.
    ids = [entry["pr_id"] for entry in entries]
    pop = pq.read_table(DATA / "AIDev/pull_request.parquet", columns=["id", "created_at"],
                        filters=[("id", "in", ids)]).to_pylist()
    if set(ids) != {row["id"] for row in pop}:
        raise ValueError("Some saved PRs are absent from the supplied AIDev-pop table")
    counts["cached_prs_matched_to_supplied_pop_table"] = len(pop)
    counts["cached_pr_created_at_min"] = min(row["created_at"] for row in pop)
    counts["cached_pr_created_at_max"] = max(row["created_at"] for row in pop)
    repo_table = pq.read_table(DATA / "AIDev/repository.parquet", columns=["full_name", "stars"]).to_pylist()
    stars = {row["full_name"].lower(): row["stars"] for row in repo_table if row["full_name"]}
    file_checks, errors = [], []
    for row in corpus:
        try:
            doc = load_workflow(Path(row["snapshot_path"]).read_text(encoding="utf-8"))
            checks = check_workflow(doc)
        except Exception as exc:
            errors.append({**row, "error": f"{type(exc).__name__}: {exc}"})
            continue
        record = {**row, "stars": stars.get(row["repo"].lower())}
        for rule, (applicable, follows) in checks.items():
            record[rule + "_applicable"] = applicable
            record[rule] = follows
        file_checks.append(record)
    base_fields = ["repo", "workflow_path", "pr_id", "base_sha", "base_commit_date", "snapshot_sha256", "stars"]
    write_csv("observed_file_checks.csv", file_checks,
              base_fields + [field for rule in RULES for field in (rule + "_applicable", rule)])
    write_csv("parse_errors.csv", errors, base_fields[:-1] + ["error"])
    counts.update({"parse_or_structure_errors": len(errors), "usable_files": len(file_checks),
                   "usable_repos": len({row["repo"] for row in file_checks})})
    if len(file_checks) < 50:
        raise SystemExit("Fewer than 50 usable files after parsing; see parse_errors.csv")
    prevalence, repo_checks = [], []
    for rule in RULES:
        applicable = [row for row in file_checks if row[rule + "_applicable"]]
        grouped = defaultdict(list)
        for row in applicable:
            grouped[row["repo"]].append(row)
        repo_rows = [{"rule_id": rule, "repo": repo, "applicable_files": len(files),
                      "files_following": sum(row[rule] for row in files), "all_follow": all(row[rule] for row in files),
                      "stars": stars.get(repo.lower())} for repo, files in sorted(grouped.items())]
        weighted = [row for row in repo_rows if isinstance(row["stars"], (int, float))
                    and math.isfinite(row["stars"]) and row["stars"] >= 0]
        total_stars = sum(row["stars"] for row in weighted)
        following_stars = sum(row["stars"] for row in weighted if row["all_follow"])
        n_follow = sum(row[rule] for row in applicable)
        repos_follow = sum(row["all_follow"] for row in repo_rows)
        prevalence.append({"rule_id": rule, "applicable_files": len(applicable), "files_following": n_follow,
                           "file_pct": percent(n_follow, len(applicable)), "applicable_repos": len(repo_rows),
                           "repos_all_follow": repos_follow, "repo_pct": percent(repos_follow, len(repo_rows)),
                           "repos_with_stars": len(weighted), "repos_missing_stars": len(repo_rows) - len(weighted),
                           "stars_denominator": total_stars, "stars_numerator": following_stars,
                           "repo_star_weighted_pct": percent(following_stars, total_stars)})
        repo_checks.extend(repo_rows)
    write_csv("rule_prevalence_observed.csv", prevalence, list(prevalence[0]))
    write_csv("observed_repo_checks.csv", repo_checks, list(repo_checks[0]))
    return prevalence


def declared():
    path = DATA / "AgentREADMEs/train-00000-of-00001.parquet"
    columns = ["content", "agent", "repository_owner", "repository_name", "file_path", "stars", "content_commit_sha"]
    rows = pq.read_table(path, columns=columns).to_pylist()
    extracted, input_files = [], set()
    for row in rows:
        repo = f"{row['repository_owner']}/{row['repository_name']}"
        file_id = f"{repo}:{row['file_path']}:{row['content_commit_sha']}"
        if file_id in input_files:
            raise ValueError("Duplicate instruction-file snapshot: " + file_id)
        input_files.add(file_id)
        for line_number, statement in statements(row["content"] or ""):
            matches = match_statement(statement)
            if matches is not None:
                extracted.append({"statement_id": len(extracted) + 1, "repo": repo, "agent": row["agent"],
                                  "file_path": row["file_path"], "content_commit_sha": row["content_commit_sha"],
                                  "stars": row["stars"], "line_number": line_number, "statement": statement,
                                  "matched_rule_ids": ";".join(matches), "file_id": file_id})
    fields = ["statement_id", "repo", "agent", "file_path", "content_commit_sha", "stars", "line_number",
              "statement", "matched_rule_ids", "file_id"]
    write_csv("agentreadmes_ci_statements.csv", extracted, fields)
    ci_files = {row["file_id"] for row in extracted}
    ci_repos = {row["repo"].lower() for row in extracted}
    prevalence = []
    for rule in RULES + ["R_other_ci"]:
        matching = [row for row in extracted if rule in row["matched_rule_ids"].split(";")]
        prevalence.append({"rule_id": rule, "matching_statements": len(matching),
                           "matching_files": len({row["file_id"] for row in matching}),
                           "matching_repos": len({row["repo"].lower() for row in matching}),
                           "files_with_any_ci_statement": len(ci_files), "repos_with_any_ci_statement": len(ci_repos),
                           "total_input_files": len(rows)})
    write_csv("rule_prevalence_declared.csv", prevalence, list(prevalence[0]))
    sample = random.Random(SEED).sample(extracted, min(60, len(extracted)))
    sample_path = ROOT / "manual_check_sample.csv"
    # Never erase the user's labels on a rerun. Other result files are regenerated.
    if not sample_path.exists():
        write_csv(sample_path.name, sample, fields + ["is_rule_statement", "correct_rule_id"])
    else:
        with sample_path.open(encoding="utf-8-sig", newline="") as handle:
            existing = list(csv.DictReader(handle))
        keys = ("statement_id", "file_id", "line_number", "statement", "matched_rule_ids")
        same = [tuple(row[key] for key in keys) for row in existing] == [
            tuple(str(row[key]) for key in keys) for row in sample]
        if not same:
            if any(row.get("is_rule_statement") or row.get("correct_rule_id") for row in existing):
                raise ValueError("Existing labelled sample differs; labels preserved, review before regenerating")
            write_csv(sample_path.name, sample, fields + ["is_rule_statement", "correct_rule_id"])
    counts = {"input_files": len(rows), "input_repos": len({f"{r['repository_owner']}/{r['repository_name']}".lower() for r in rows}),
              "file_types": dict(Counter(row["agent"] for row in rows)), "ci_statements": len(extracted),
              "files_with_ci": len(ci_files), "repos_with_ci": len(ci_repos), "manual_sample": len(sample), "seed": SEED}
    return prevalence, counts


def report(observed_rows, declared_rows, observed_counts, declared_counts):
    inputs = [PILOT / "agent_workflow_prs.json", PILOT / "snapshot_manifest.json",
              DATA / "AIDev/repository.parquet", DATA / "AgentREADMEs/train-00000-of-00001.parquet"]
    provenance = {"run_date": "2026-10-06", "aidev_cache_version": "legacy pilot; HF revision not recorded",
                  "aidev_table_version": "supplied local refreshed tables; HF revision not independently established",
                  "agentreadmes_version": "local 2303-file snapshot; HF revision not recorded; content commits retained",
                  "observed": observed_counts, "declared": declared_counts,
                  "packages": {"ruamel.yaml": "0.18.16", "pyarrow": pyarrow.__version__},
                  "sources": [{"path": str(p), "bytes": p.stat().st_size, "sha256": sha256(p)} for p in inputs]}
    (ROOT / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    (ROOT / "rule_patterns.json").write_text(json.dumps({"ci_filter": CI_PATTERNS, "rule_patterns_all_required": PATTERNS}, indent=2) + "\n", encoding="utf-8")
    declarations = {row["rule_id"]: row for row in declared_rows}
    table = ["| Rule | Observed files following/applicable (%) | Observed repos all/applicable (%) | Declared repos* | Declared files* |",
             "|---|---:|---:|---:|---:|"]
    for row in observed_rows:
        d = declarations[row["rule_id"]]
        table.append(f"| {row['rule_id']} | {row['files_following']}/{row['applicable_files']} ({row['file_pct']}%) | "
                     f"{row['repos_all_follow']}/{row['applicable_repos']} ({row['repo_pct']}%) | {d['matching_repos']} | {d['matching_files']} |")
    text = """# Candidate CI/CD rule evidence

Computed 2026-10-06. Counts only: literal observed practices and keyword-matched instruction statements. These do not establish vulnerabilities, binding policies, or agent compliance.

## Inputs and versions

- Raw datasets are read from `E:\\!My Files\\CS\\Grammar`; all outputs are in this folder. No raw data was modified.
- Before-files reuse `../AIDev/security_scan/base/` and its agent-only PR manifest. Human CI-export PRs are excluded. This is the historical pilot extraction, not a new extraction of all v5 PRs. Its HF revision was not recorded; do not label it v5. Legacy local `pull_request.parquet` has 71,677 rows; supplied refreshed E: table has 361,296. The cached PR dates are recorded below. `provenance.json` fingerprints the exact manifests and inputs.
- All 95 cached agent PR IDs match the supplied AIDev-pop `pull_request` table. Only `id` and `created_at` for these IDs are read. No full PR table or patch table is loaded. Stars come from the supplied `repository.parquet` (`full_name`, `stars` only); its original HF revision is not recorded.
- AgentREADMEs is the supplied 2,303-file snapshot, with per-file `content_commit_sha` retained. It covers CLAUDE.md, AGENTS.md, and copilot-instructions.md. The dataset metadata is from approximately October 2025, not a longitudinal corpus. Local dataset SHA-256 is recorded; a precise HF download revision is not assumed.

## Filtering counts

```json
OBSERVED_COUNTS
```

```json
DECLARED_COUNTS
```

## Counts

SUMMARY_TABLE

*Declared columns count files/repos with at least one **candidate keyword match**, pending manual validation. Statements can match multiple rules; columns cannot be summed as disjoint categories. `R_other_ci` has OTHER_REPOS repositories and OTHER_FILES files.

## Definitions and reproducibility

- The observed unit is one existing before-workflow per repository/path. Dedup selects the smallest base commit **committer timestamp** among available competing snapshots, not a sorted SHA or PR ID. GitHub date responses for the 17 competing commits are cached in `base_commit_dates.json`. Single-snapshot keys do not need a timestamp for selection. Ties use SHA then PR ID. This does not establish ancestry across branches or the earliest historical version of a file.
- `corpus_candidates.csv` shows every available candidate and selection; `observed_corpus.csv` lists selected snapshots and content hashes. Added files have no before version and are excluded. Files missing a before snapshot would be excluded and counted.
- YAML uses ruamel.yaml 0.18.16 round-trip parsing with duplicate-key rejection. `on` and boolean `True` trigger keys are supported. Parse errors and structurally unusable roots/jobs are excluded and listed in `parse_errors.csv`; zero errors is not a full workflow-validity result.
- R1/R9/R10 check key presence only; they do not validate permission scope, timeout value, or concurrency behavior. R2 checks literal `permissions: write-all` recursively. R3/R4 check event presence, not whether those events are unsafe in context.
- R5 searches only GitHub expression interpolations inside run steps for the nine specified property paths, including whitespace variants. It is a lexical proxy, not data-flow analysis. Environment-variable and other indirect flows are outside this check.
- R6/R7 include step actions and job-level reusable workflow references. Both exclude local `./` and `docker://` uses; R7 adds first-party owners. GitHub owner comparisons ignore case. A pinned reference ends in `@` plus exactly 40 hexadecimal characters. No remote existence verification is performed.
- R8 accepts explicit boolean false or string `false` for checkout persist-credentials. R11 flags literal boolean/string true at job or step level. Expressions are not evaluated. A quoted false is not treated as truthy by Python.
- R5/R6/R7/R8 have applicability flags. Empty applicable sets do not enter denominators; their vacuous boolean results are not counted. Repo success means **all applicable sampled before-files** follow. It does not mean every workflow in the repository follows.
- Weighted repo percent is `100 * sum(stars of all-follow repos) / sum(stars of applicable repos with known nonnegative stars)`. Weight each repo once. Missing-star counts and exact numerator/denominator are in `rule_prevalence_observed.csv`; a zero denominator yields an unavailable value.
- Instruction splitting preserves source line numbers: nonempty lines (including bullets/code/headings) are split at sentence-ending punctuation followed by whitespace and an uppercase letter/digit/backtick. File paths and ordinary inline dots are preserved. Wrapped sentences may be split across lines.
- `rule_patterns.json` documents every regex. All patterns listed for a rule must match the same statement. The CI filter uses boundaries, plural forms, and pinning variants. It also includes `workflow_run` and `persist-credentials` so isolated mentions of R4/R8 are not lost. This small explicit augmentation of the supplied filter is documented here.
- R6 requires third-party/external action wording; R7 is a broad action-pinning candidate and may overlap R6. Keyword direction, obligation, exceptions, and authority are not resolved. A descriptive, permissive, or contrary statement can match. English lexical patterns miss other languages and paraphrases. Generic timeouts, tokens, and concurrency can be unrelated to CI.
- `manual_check_sample.csv` is a seeded random sample of 60 **all CI candidate statements**, including R_other_ci. Fill `is_rule_statement` with y/n and `correct_rule_id` with applicable IDs or R_other_ci. Reruns preserve matching samples and never overwrite a changed sample with existing labels; an entirely unlabelled sample can be regenerated. This sample is not a balanced per-rule audit.

## Caveats

These are repositories where an agent later edited a workflow, selected through the earlier pilot's CI-export overlap and retrieval/sampling frame. The corpus contains only touched workflows, not all workflows or a representative sample of GitHub. Some before-files may already contain agent-written content. Earliest available timestamps reduce repeated snapshots but do not remove that contamination. No v5-wide prevalence is claimed.

The AIDev and AgentREADMEs samples are separate snapshots/populations. Their two counts are not matched historical policy-versus-behavior observations and cannot establish whether a particular agent saw an instruction. Stars are a snapshot weighting choice, not evidence that a practice is required or correct. No results beyond the counts are inferred.

## Commands

From the workspace root (Python with pyarrow installed):

```powershell
python -m pip install --target "Experiments/Data/rule_mining/_deps" --no-deps ruamel.yaml==0.18.16
python "Experiments/Data/rule_mining/prepare_metadata.py"
python "Experiments/Data/rule_mining/mine.py"
python "Experiments/Data/rule_mining/verify_outputs.py"
```

The first command downloads the parser without changing the global Python installation. The second fetches public commit metadata only on a cache miss. The third runs the unit tests before reading datasets, then uses local files and the metadata cache without network. Test output is saved in `test_results.txt`. The fourth independently reconciles exported counts, dedup selection, and sampling, saving `verification.json`.

## Sources

- [AgentREADMEs dataset and schema](https://huggingface.co/datasets/hao-li/AgentREADMEs)
- [Agent READMEs paper](https://arxiv.org/abs/2511.12884)
- [AIDev refreshed memory-safe loading documentation](https://huggingface.co/datasets/hao-li/AIDev-7.6M/blob/main/scripts/load_aidev.py)
- The original attached task supplies the eleven literal practices; they are candidate practices, not a literature-validated normative rule set.
"""
    text = text.replace("OBSERVED_COUNTS", json.dumps(observed_counts, indent=2)).replace("DECLARED_COUNTS", json.dumps(declared_counts, indent=2))
    text = text.replace("SUMMARY_TABLE", "\n".join(table)).replace("OTHER_REPOS", str(declarations["R_other_ci"]["matching_repos"]))
    text = text.replace("OTHER_FILES", str(declarations["R_other_ci"]["matching_files"]))
    (ROOT / "README.md").write_text(text, encoding="utf-8")


def main():
    with (ROOT / "test_results.txt").open("w", encoding="utf-8") as handle:
        suite = unittest.defaultTestLoader.discover(str(ROOT), pattern="test_rules.py")
        result = unittest.TextTestRunner(stream=handle, verbosity=2).run(suite)
    if not result.wasSuccessful() or not result.testsRun:
        raise SystemExit("Unit tests failed or were absent; see test_results.txt. Data was not analyzed.")
    print(f"Unit tests passed: {result.testsRun}")
    entries, corpus, counts = build_corpus()
    observed_rows = observed(entries, corpus, counts)
    declared_rows, declared_counts = declared()
    report(observed_rows, declared_rows, counts, declared_counts)
    print(json.dumps({"observed": counts, "declared": declared_counts}, indent=2))


if __name__ == "__main__":
    main()
