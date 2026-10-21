# Agentic Policy Compliance

Research code for assessing security and correctness changes in agent-attributed GitHub Actions workflow edits. The current pipeline compares historical before/after workflow files using zizmor, actionlint, literal custom rules, and relative change checks.

Scanner findings are candidate policy signals, not proof of policy adoption, agent exposure, or an actual exploit. This repository does not currently evaluate agents executing natural-language agentic workflows.

## Code

- [Pipeline setup, commands and limitations](Experiments/Policy%20Oracle%20Pipeline/paper_a/README.md)
- [Original custom checks](Experiments/Data/rule_mining/mine.py)

The existing directory layout is preserved so the validated code and recorded source hashes remain intact. Git attributes disable line-ending conversion for the frozen source.

## Data and tools

Raw datasets, results, retrieval caches, binaries, local dependencies and machine-specific output paths are excluded from Git. Configure an output directory and supply the pinned tools as described in the pipeline README. Keep the archived data and its provenance separately.

## Validation

After restoration on 15 October 2026: 48 unit tests passed, all 485 historical pilot comparisons matched, and full-output verification passed. Four scanner source files match the completed run hashes. The missing recovery script was reconstructed from recorded edits and passes the history tests; no independent original hash was available for that script.
