"""Resumable independent Codex reviews of existing evidence packages.

Uses saved ChatGPT CLI authentication. Never runs scanners or workflow code.
"""
import argparse
import ctypes
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pandas as pd

LOCK = threading.Lock()
STOP = threading.Event()
CAPACITY_UNTIL = 0.0


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{threading.get_ident()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def prepare(root, run, count, model, effort, workers):
    if (run / "run_config.json").exists():
        raise ValueError("Run already prepared; use run to resume it.")
    run.mkdir(parents=True, exist_ok=True)
    active = set(read(root / "case_index.json"))
    # Selection code reads identifiers/rule labels only, not author metadata.
    metadata = pd.read_parquet(root / "case_metadata.parquet", columns=["case_id", "oracle", "rule_id"])
    metadata = metadata[metadata.case_id.isin(active)]
    rng = random.Random(42)
    groups = []
    for _, group in metadata.groupby(["oracle", "rule_id"], sort=True):
        ids = sorted(group.case_id)
        rng.shuffle(ids)
        groups.append(ids)
    queue = []
    # Interleave rules so a partial run also covers many rules.
    for round_number in range(max(map(len, groups))):
        for group in groups:
            if round_number < len(group):
                queue.append(group[round_number])
            if len(queue) == min(count, len(metadata)):
                break
        if len(queue) == min(count, len(metadata)):
            break
    for name in ["prompt.md", "output_schema.json"]:
        shutil.copyfile(root / name, run / name)
    config = dict(created_at=now(), export_root=str(root), target=len(queue), model=model,
                  reasoning_effort=effort, workers=workers, seed=42,
                  selection="Random order within each oracle/rule; round-robin across rules. This is a balanced exploratory subset, not a population-rate sample.",
                  auth="saved ChatGPT login; API key environment variables removed; no credit reset or paid fallback",
                  export_manifest_present=(root / "manifest.json").exists(),
                  prompt_sha256=sha((run / "prompt.md").read_bytes()),
                  schema_sha256=sha((run / "output_schema.json").read_bytes()),
                  timeout_seconds=900, max_attempts=2)
    write(run / "queue.json", queue)
    write(run / "run_config.json", config)
    (run / "isolated_workdir").mkdir(exist_ok=True)
    write(run / "progress.json", dict(state="prepared", target=len(queue), completed=0, failed=0, started=0, updated_at=now()))
    (run / "README.md").write_text(
        "# Independent Codex case reviews\n\n"
        "progress.json is the live status. assessments/ contains validated model outputs. attempts/ contains per-call events, errors, and receipts. requests/ contains the exact full judge inputs (including all workflow text). queue.json fixes selection and ordering. No pilot judgments are reused.\n\n"
        "Run with the same command and run directory to resume; successful assessments are retained. Create STOP to stop scheduling additional cases (in-flight reviews finish). No API-key fallback, credit reset, or usage-limit workaround is used.\n\n"
        "The model judges directly with shell and web tools disabled. The runner only packages inputs and checks output structure, instance coverage, and verbatim evidence. Those checks are not human validation. Agent and sampling metadata are not sent, but identity may be inferable from workflow content.\n",
        encoding="utf-8")
    print(json.dumps(config, indent=2), flush=True)


def request_text(root, run, case_id):
    case = read(root / "cases" / (case_id + ".json"))
    rule_path = root / case["rule_file"]
    snapshot_path = root / case["snapshot_file"]
    rule, snapshot = read(rule_path), read(snapshot_path)
    assert case["case_id"] == case_id and rule["rule_id"] == case["rule_id"]
    for side in ["before", "after"]:
        assert sha(snapshot[side + "_yaml"].encode("utf-8")) == snapshot[side + "_sha256"]
    prefix = (run / "prompt.md").read_text(encoding="utf-8")
    # The full referenced files are embedded. No evidence is truncated.
    adapter = """\nEXECUTION ADAPTER (revision 2): All referenced files are fully embedded below instead of being read from disk. Use only this message. Do not call tools or retrieve external sources. The rule and case JSON and complete snapshot (including full YAML and diff) follow. Return only the required JSON. Assess all instances, even if the finding has an important exception. Pattern labels must be provisional. Do not assume that a nonfatal step weakens the job gate: inspect downstream aggregation. Do not assume a custom runner label is invalid when runner configuration is missing.

EVIDENCE FORMAT REQUIREMENT: Each mechanisms[].evidence[].snippet MUST be an exact contiguous substring of the specified before_yaml or after_yaml STRING, after JSON decoding. Prefer a short single-line snippet such as 'continue-on-error: true' or 'uses: actions/checkout@v4', without leading indentation. Do NOT join nonadjacent lines, add ellipses, reindent multiline blocks, or insert line numbers into snippets. Metadata such as before_exists:false and scanner diagnostic messages are NOT workflow YAML evidence: discuss them in explanation/limitations, never quote them as a before/after YAML snippet. An absent before file has no YAML to quote; cite actual after YAML and explain the absence in prose. Do not fabricate evidence to fill an empty side.\n"""
    prompt = prefix + adapter + "\nRULE FILE:\n" + json.dumps(rule, ensure_ascii=False) + "\nCASE FILE:\n" + json.dumps(case, ensure_ascii=False) + "\nFULL SNAPSHOT FILE:\n" + json.dumps(snapshot, ensure_ascii=False)
    request_path = run / "requests" / (case_id + ".txt")
    request_path.parent.mkdir(exist_ok=True)
    request_path.write_text(prompt, encoding="utf-8")
    receipt = dict(case_id=case_id, input_sha256=sha(prompt.encode("utf-8")), input_characters=len(prompt),
                   case_sha256=sha((root / "cases" / (case_id + ".json")).read_bytes()),
                   rule_sha256=sha(rule_path.read_bytes()), snapshot_sha256=sha(snapshot_path.read_bytes()),
                   finding_instances=len(case["finding_instances"]))
    return prompt, case, snapshot, receipt


def validate(answer, case, snapshot, schema):
    jsonschema.validate(answer, schema)
    assert answer["case_id"] == case["case_id"], "Wrong case ID"
    indices = [item["instance_index"] for item in answer["instance_assessments"]]
    assert sorted(indices) == list(range(len(case["finding_instances"]))), "Instance coverage mismatch"
    identities = [item["mechanism_id"] for item in answer["mechanisms"]]
    assert len(set(identities)) == len(identities), "Duplicate mechanism IDs"
    for item in answer["instance_assessments"]:
        assert set(item["mechanism_ids"]) <= set(identities), "Unknown mechanism reference"
    for mechanism in answer["mechanisms"]:
        for quote in mechanism["evidence"]:
            assert quote["snippet"] and quote["snippet"] in snapshot[quote["side"] + "_yaml"], (
                "Evidence snippet not verbatim in " + quote["side"] + "_yaml at " + quote["location"]
                + ": " + repr(quote["snippet"][:300]))


def run_batch(run, limit=None):
    config = read(run / "run_config.json")
    root = Path(config["export_root"])
    schema = read(run / "output_schema.json")
    runner_bytes = Path(__file__).read_bytes()
    runner_hash = sha(runner_bytes)
    (run / "runner_sources").mkdir(exist_ok=True)
    (run / "runner_sources" / (runner_hash + ".py")).write_bytes(runner_bytes)
    queue = read(run / "queue.json")
    codex = shutil.which("codex.exe") or shutil.which("codex")
    if not codex:
        raise RuntimeError("Codex CLI not found")
    cli_version = subprocess.run([codex, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    auth = subprocess.run([codex, "login", "status"], capture_output=True, text=True)
    if auth.returncode or "ChatGPT" not in auth.stdout + auth.stderr:
        raise RuntimeError("Expected existing ChatGPT CLI login; refusing API-key fallback")
    (run / "assessments").mkdir(exist_ok=True)
    (run / "attempts").mkdir(exist_ok=True)
    remaining = [case_id for case_id in queue if not (run / "assessments" / (case_id + ".json")).exists()]
    if limit:
        remaining = remaining[:limit]
    progress = dict(state="running", target=len(queue), completed=len(queue) - len([case_id for case_id in queue if not (run / "assessments" / (case_id + ".json")).exists()]),
                    failed=0, started=0, active=0, consecutive_failures=0,
                    runner_pid=os.getpid(), runner_source_sha256=runner_hash,
                    cli_version=cli_version, updated_at=now())

    def update(**changes):
        with LOCK:
            progress.update(changes)
            progress["updated_at"] = now()
            write(run / "progress.json", progress)

    update()
    env = os.environ.copy()
    for key in ["OPENAI_API_KEY", "CODEX_API_KEY"]:
        env.pop(key, None)
    env["PYTHONIOENCODING"] = "utf-8"
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    def review(case_id):
        global CAPACITY_UNTIL
        while time.monotonic() < CAPACITY_UNTIL:
            if STOP.is_set() or (run / "STOP").exists():
                return "stopped"
            time.sleep(2)
        if STOP.is_set() or (run / "STOP").exists():
            return "stopped"
        with LOCK:
            progress["started"] += 1
            progress["active"] += 1
        update()
        outcome = "failed"
        try:
            prompt, case, snapshot, receipt = request_text(root, run, case_id)
            folder = run / "attempts" / case_id
            folder.mkdir(exist_ok=True)
            retry_feedback = ""
            for attempt in range(1, config["max_attempts"] + 1):
                if STOP.is_set() or (run / "STOP").exists():
                    outcome = "stopped"
                    break
                attempt_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%f') + f"_{attempt}"
                answer_path = folder / f"attempt_{attempt_id}.answer.json"
                events_path = folder / f"attempt_{attempt_id}.events.jsonl"
                error_path = folder / f"attempt_{attempt_id}.stderr.txt"
                command = [codex, "exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check",
                           "--sandbox", "read-only", "--model", config["model"],
                           "-c", 'model_reasoning_effort="' + config["reasoning_effort"] + '"',
                           "-c", 'forced_login_method="chatgpt"',
                           "-c", "features.shell_tool=false", "-c", 'web_search="disabled"',
                           "-c", "project_doc_max_bytes=0", "-c", "hide_agent_reasoning=true",
                           "--output-schema", str(run / "output_schema.json"),
                           "--output-last-message", str(answer_path), "--json", "-"]
                record = dict(receipt, attempt=attempt, started_at=now(), model=config["model"],
                              reasoning_effort=config["reasoning_effort"], cli_version=cli_version,
                              command=command, validation="not_run")
                attempt_prompt = prompt + retry_feedback
                record["attempt_input_sha256"] = sha(attempt_prompt.encode("utf-8"))
                record["retry_feedback"] = retry_feedback
                try:
                    with events_path.open("w", encoding="utf-8") as stdout, error_path.open("w", encoding="utf-8") as stderr:
                        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                                   cwd=run / "isolated_workdir", env=env, creationflags=flags)
                        try:
                            process.communicate(attempt_prompt.encode("utf-8"), timeout=config["timeout_seconds"])
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate()
                            raise TimeoutError("Codex case exceeded 900 seconds")
                    record["exit_code"] = process.returncode
                    # Preserve only concise failure/event information here; raw events stay on disk.
                    events = []
                    for line in events_path.read_text(encoding="utf-8").splitlines():
                        try:
                            events.append(json.loads(line))
                        except ValueError:
                            pass
                    record["usage"] = [item.get("usage") for item in events if item.get("type") == "turn.completed"]
                    record["thread_ids"] = [item.get("thread_id") for item in events if item.get("type") == "thread.started"]
                    failures = [item for item in events if item.get("type") in ["error", "turn.failed"]]
                    failure_text = json.dumps(failures) + error_path.read_text(encoding="utf-8")
                    lowered = failure_text.lower()
                    # Do not work around account limits or switch billing/authentication.
                    if any(marker in lowered for marker in ["usage limit", "rate limit", "quota exceeded", "insufficient_quota", "usage_limit_reached", "rate_limit_exceeded"]):
                        record["error"] = "Account/usage limit reached; run stopped with completed outputs preserved."
                        STOP.set()
                        update(state="stopped_usage_limit", stop_reason=record["error"])
                        outcome = "stopped"
                        break
                    if "at capacity" in lowered or "temporarily unavailable" in lowered:
                        record["error"] = "Model temporarily unavailable; same case will be retried after backoff."
                        CAPACITY_UNTIL = max(CAPACITY_UNTIL, time.monotonic() + 120)
                        update(state="waiting_model_capacity", retry_after_seconds=120)
                        outcome = "deferred"
                        break
                    if process.returncode:
                        raise RuntimeError("Codex failed: " + failure_text[-1800:])
                    forbidden = [item for item in events if item.get("type") == "item.completed" and item.get("item", {}).get("type") in ["command_execution", "mcp_tool_call", "web_search", "file_change"]]
                    assert not forbidden, "Judge used tools despite the evidence-only protocol"
                    answer = read(answer_path)
                    validate(answer, case, snapshot, schema)
                    record["validation"] = "passed: schema, case ID, instance coverage, mechanism links, verbatim snippets"
                    write(run / "assessments" / (case_id + ".json"), answer)
                    (folder / "failure.json").unlink(missing_ok=True)
                    outcome = "completed"
                    break
                except Exception as exc:
                    record["error"] = str(exc)
                    retry_feedback = (
                        "\nVALIDATION FEEDBACK FROM THE PREVIOUS ATTEMPT: " + str(exc)
                        + "\nReturn a new complete assessment. For evidence use short single-line exact substrings copied from the relevant decoded workflow YAML. Never use metadata, a diagnostic, ellipses, or reconstructed multiline excerpts as workflow evidence. Keep absence claims and qualifications in prose fields.\n")
                    if attempt < config["max_attempts"]:
                        time.sleep(5)
                finally:
                    record["finished_at"] = now()
                    write(folder / f"attempt_{attempt_id}.receipt.json", record)
            if outcome == "failed":
                write(folder / "failure.json", dict(case_id=case_id, error="No valid assessment after bounded attempts", timestamp=now()))
        except Exception as exc:
            write(run / "attempts" / case_id / "failure.json", dict(case_id=case_id, error=str(exc), timestamp=now()))
        finally:
            with LOCK:
                progress["active"] -= 1
                progress["completed"] += outcome == "completed"
                progress["failed"] += outcome == "failed"
                if outcome == "failed":
                    progress["consecutive_failures"] += 1
                elif outcome == "completed":
                    progress["consecutive_failures"] = 0
                if progress["consecutive_failures"] >= 5:
                    STOP.set()
                    progress["state"] = "stopped_repeated_failures"
                    progress["stop_reason"] = "Five consecutive failed cases; inspect errors before resuming."
            update()
            print(now(), case_id, outcome, "completed", progress["completed"], flush=True)
        return outcome

    if os.name == "nt":
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
    try:
        with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
            # Bounded scheduling: stop promptly rather than queueing 5,000 futures.
            waiting = deque(remaining)
            pending = {}
            while pending or waiting:
                if (run / "STOP").exists() or STOP.is_set():
                    waiting.clear()
                while waiting and len(pending) < config["workers"] and time.monotonic() >= CAPACITY_UNTIL:
                    case_id = waiting.popleft()
                    pending[executor.submit(review, case_id)] = case_id
                    update(state="running")
                finished = [future for future in pending if future.done()]
                if not finished:
                    time.sleep(1)
                    continue
                for future in finished:
                    outcome = future.result()
                    case_id = pending.pop(future)
                    if outcome == "deferred" and not STOP.is_set():
                        waiting.appendleft(case_id)
        if not STOP.is_set():
            update(state="stopped_by_file" if (run / "STOP").exists() else ("complete" if progress["completed"] == len(queue) else "partial"))
    finally:
        if os.name == "nt":
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
    print(json.dumps(progress, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["prepare", "run"])
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--export-root", type=Path)
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument("--model", default="gpt-6.1-sol")
    parser.add_argument("--effort", default="medium")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.export_root.resolve(), args.run_dir.resolve(), args.count, args.model, args.effort, args.workers)
    else:
        # An OS lock prevents two resumptions from reviewing the same queue concurrently.
        run_lock = (args.run_dir.resolve() / "runner.lock").open("a+b")
        if os.name == "nt":
            import msvcrt
            if run_lock.tell() == 0:
                run_lock.write(b"0")
                run_lock.flush()
            run_lock.seek(0)
            msvcrt.locking(run_lock.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            run_batch(args.run_dir.resolve(), args.limit)
        finally:
            run_lock.close()
