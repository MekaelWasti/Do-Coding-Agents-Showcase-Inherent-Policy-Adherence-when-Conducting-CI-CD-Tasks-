# Paper A → Paper B policy handoff

`policy_catalog.json` is a **provisional candidate export**, not a completed validation result. It reuses exact Paper A rule IDs and existing oracle mappings. The original rule catalog's SHA-256 and the AIDev dataset revision are recorded.

For each eventual validated rule, preserve: a stable rule ID; unambiguous statement; origin (`external`, `repo_stated`, or `implicit`); applicability/scope; source links and relationship; validation status; exact oracle/rule mapping; and known limits. If semantics change materially, version the rule/export rather than silently reusing an old definition.

The four starting candidates provide a small plumbing example. They were not selected by a preregistered process and are not a final ranking. Paper A must still justify the selection, validate cases, and decide the compliance scope. Related Scorecard/checklist guidance does not mean those broader checks are reproduced exactly.

Paper B reads this file rather than defining a second policy set in its code. To try another set, edit Paper B's selection config. To revise a requirement, edit/version this export and regenerate the plan. Never mark a candidate validated merely to remove a blocker.
