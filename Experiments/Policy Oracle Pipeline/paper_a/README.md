# Paper A: workflow change assessment

Recover historical GitHub Actions workflow changes and assess before/after states with zizmor, actionlint, the original R1–R11 literal checks, and relative change predicates. One record represents one workflow file in one PR/change. Findings are matched into introduced, fixed and persisted instances; errors and ambiguous matches remain explicit.

These are scanner findings and candidate requirements, not proof that a repository adopted a policy or an agent saw it. Generated workflows and repository concentration require separate analysis. Historical matching profiles reproduce pilot conventions; primary pairs use the default matcher.

## Repository contents

Commit Python source, tests, dependency/tool versions, documentation and example configuration. The custom-check dependency is `Experiments/Data/rule_mining/mine.py`. The root `.gitignore` excludes raw datasets, results, caches, executables, vendored dependencies and real output paths. This checkout alone is not a complete archived experiment.

## Setup

The validated Windows environment used Python 3.14 and `requirements.txt`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r "Experiments/Policy Oracle Pipeline/paper_a/requirements.txt"
```

1. Copy `output_location.example.json` to `output_location.json` and set `outputs` to your generated-data directory. Without this file, `paths.py` uses this directory's `outputs/`.
2. Put zizmor 1.30.1 and actionlint 1.7.12 at `tools/zizmor.exe` and `tools/actionlint.exe`. `tools/tool_versions.json` records the exact Windows executable hashes. `actionlint_provenance.json` includes the official release archive checksum. These binaries are not committed; this runner currently uses Windows executable paths.
3. Restore original pilot references under `Experiments/Data/AIDev/security_scan/` and `Experiments/Data/SWE-chat/workflow_zizmor_pilot/` for regression. SWE-chat conversion expects its original data layout. Standalone rule mining also requires adjusting the local raw-data root in `mine.py`.
4. Network retrieval requires authenticated GitHub CLI (`gh`); never commit credentials.
5. Rebuilding the catalogue with `build_rules.py` requires the official `zizmorcore/zizmor` v1.30.1 source archive at `sources/zizmor-1.30.1.tar.gz`. An existing completed output folder already contains the catalogue.

The frozen AIDev input is `hao-li/AIDev-7.6M@37bbe1533e26cc1e1374917dba1186d1c8a4dc81` (official v5 WIP), not an unpublished `hao-li/AIDev@v5` tag. The separate v4 pilot cohort pin is `hao-li/AIDev@bc7996907b404359f581c43d5160afe6ed599a14`. Preserve generated provenance and qualifications with archived data.

## Checks

From this directory, using the environment's Python:

```powershell
python -m unittest tests test_history test_public_diff
python verify_run.py
python regression.py
```

Verification reconciles source/input hashes, identities, counts, source-linked rules, errors and review records. Regression compares existing legacy results with original reference CSVs; it does not rescan them. All 48 tests, full-output verification and 485 pilot comparisons passed after restoration on 15 October 2026.

The four scanner source hashes match the completed run metadata. `recover_pairs.py` was reconstructed from its recorded creation and 13 subsequent updates, with exact patch matching. No separate original-file hash was available for that recovery script; history tests pass.

## Entry points

- `stream_aidev.py`, `extract_commits.py`, `prefetch_parents.py`, `recover_pairs.py`: selection and historical recovery.
- `convert_local.py`, `recover_swechat.py`: strict prompt-linked SWE-chat cases.
- `audit_comparisons.py`, `assemble_pairs.py`: metadata audits and unified pairs.
- `build_rules.py`: sourced rule catalogue and qualified checklist coverage.
- `oracles.py`, `legacy_zizmor.py`, `run_oracles.py`: checks and finding matching.
- `resume_pipeline.py`: sequential recovery, assembly, scanning and checks.

Use only one coordinator per output directory. Output Parquet files publish at the end; caches support reuse but the current runner does not checkpoint complete output batches. Scanners never execute workflows. Missing data and failed checks are not clean results.
