"""Run every pair in bounded batches; publish outputs only after the run finishes."""
import argparse
import collections
import csv
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
from oracles import analyze
from build_rules import write

ROOT = Path(__file__).resolve().parent
from paths import OUT
GROUPS = ['privilege', 'credentials', 'execution_integrity', 'supply_chain',
          'workflow_hygiene', 'workflow_correctness', 'ci_integrity']
PAIR_FIELDS = ['pair_id', 'source', 'repo', 'commit_or_pr', 'agent_name',
               'author_class', 'path', 'base_sha', 'head_sha', 'change_type',
               'link_quality', 'conversion_status']
FINDING_SCHEMA = pa.schema([
    (name, pa.bool_() if name == 'needs_review' else pa.int64() if name == 'line' else pa.string())
    for name in ['pair_id', 'status', 'match_basis', 'needs_review', 'before_evidence',
                 'oracle', 'rule_id', 'severity', 'anchor', 'detail', 'job', 'step',
                 'evidence', 'line', 'source', 'repo', 'commit_or_pr', 'rule_group']
])
SUMMARY_SCHEMA = pa.schema(
    [(name, pa.string()) for name in PAIR_FIELDS + ['scan_status', 'oracle_errors', 'context_gaps', 'side_scan_counts', 'partial_findings']]
    + [(name, pa.bool_()) for name in ['all_oracles_complete', 'all_checks_decidable']]
    + [('observed_group_counts', pa.string())]
    + [(g + '_' + state, pa.int64()) for g in GROUPS for state in ['introduced', 'fixed', 'persisted']]
    + [('zizmor_status', pa.string()), ('zizmor_introduced', pa.int64())]
)


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def normalize(pair, result, found, catalog):
    """Attach rule groups and retain incomplete checks as null counts."""
    for finding in found + result.get('partial_findings', []):
        rule_id = finding['rule_id']
        if rule_id not in catalog:
            if not rule_id.startswith('A_'):
                raise ValueError('Unmapped rule ' + rule_id)
            catalog[rule_id] = dict(
                rule_id=rule_id, statement='Resolve actionlint ' + rule_id[2:] + ' diagnostic',
                source='https://github.com/rhysd/actionlint/blob/v1.7.12/docs/checks.md',
                source_reference='Pinned actionlint 1.7.12', evidence_type='artifact',
                rule_group='workflow_correctness', check_type='actionlint',
                check='oracles.check_actionlint', audit_id='',
                qualification='Isolated YAML, no shellcheck/pyflakes or repository action configuration; task success is separate')
        finding.update(source=pair['source'], repo=pair['repo'],
                       commit_or_pr=pair['commit_or_pr'], rule_group=catalog[rule_id]['rule_group'])
    counts = collections.Counter((f['rule_group'], f['status']) for f in found)
    summary = {k: pair.get(k) for k in PAIR_FIELDS}
    summary.update(scan_status=json.dumps(result['statuses']),
                   oracle_errors=json.dumps(result['errors']),
                   context_gaps=json.dumps(result['context_gaps']),
                   side_scan_counts=json.dumps(result.get('side_scan_counts', {})),
                   partial_findings=json.dumps(result.get('partial_findings', [])))
    complete = not result['errors'] and all(result['statuses'].get(k) == 'analyzed'
                                          for k in ['zizmor', 'actionlint', 'custom', 'change'])
    summary['all_oracles_complete'] = complete
    summary['all_checks_decidable'] = complete and not result['context_gaps']
    summary['observed_group_counts'] = json.dumps({g + ':' + state: n for (g, state), n in counts.items()})
    for g in GROUPS:
        decidable = complete and not (g == 'privilege' and result['context_gaps'])
        for state in ['introduced', 'fixed', 'persisted']:
            summary[g + '_' + state] = counts[(g, state)] if decidable else None
    summary['zizmor_status'] = result['statuses'].get('zizmor', 'excluded')
    summary['zizmor_introduced'] = (sum(f['oracle'] == 'zizmor' and f['status'] == 'introduced' for f in found)
                                   if summary['zizmor_status'] == 'analyzed' else None)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default=str(OUT / 'legacy_pairs.parquet'))
    parser.add_argument('--output', default=str(OUT / 'legacy_oracle_run'))
    parser.add_argument('--batch-size', type=int, default=256)
    args = parser.parse_args()
    if args.batch_size < 1:
        parser.error('--batch-size must be positive')
    target = Path(args.output)
    target.mkdir(parents=True, exist_ok=True)
    names = ['run_oracles.py', 'oracles.py', 'legacy_zizmor.py', 'build_rules.py']
    fingerprints = {name: file_sha(ROOT / name) for name in names}
    input_sha = file_sha(args.input)
    metadata = dict(input=str(Path(args.input).resolve()), input_sha256=input_sha,
                    code_sha256=fingerprints, phase='running', batch_size=args.batch_size)
    metadata_path = target / 'run_metadata.json'
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    with (OUT / 'rule_catalog.csv').open(encoding='utf-8', newline='') as stream:
        catalog = {r['rule_id']: r for r in csv.DictReader(stream)}
    schemas = {'findings': FINDING_SCHEMA, 'pairs_summary': SUMMARY_SCHEMA,
               'unmatched_findings': FINDING_SCHEMA}
    counts = collections.Counter()
    errors = collections.Counter()
    source = pq.ParquetFile(args.input)
    total = source.metadata.num_rows
    with ExitStack() as stack:
        writers = {name: stack.enter_context(pq.ParquetWriter(target / (name + '.partial.parquet'), schema))
                   for name, schema in schemas.items()}
        pool = stack.enter_context(ThreadPoolExecutor(max_workers=8))
        for batch in source.iter_batches(batch_size=args.batch_size):
            pairs = batch.to_pylist()
            rows = {name: [] for name in schemas}
            for pair, (result, found) in zip(pairs, pool.map(analyze, pairs)):
                rows['pairs_summary'].append(normalize(pair, result, found, catalog))
                rows['findings'].extend(found)
                rows['unmatched_findings'].extend(f for f in found if f['match_basis'] == 'unmatched' or f['needs_review'])
                errors.update(result['errors'].keys())
            for name, values in rows.items():
                writers[name].write_table(pa.Table.from_pylist(values, schema=schemas[name]))
                counts[name] += len(values)
            print(f"Analyzed {counts['pairs_summary']}/{total} workflow pairs", flush=True)
    # Detect a changed assembly instead of presenting mixed provenance as final.
    if file_sha(args.input) != input_sha:
        metadata.update(phase='input_changed')
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
        raise RuntimeError('Input changed during run; partial artifacts have not been published')
    with (OUT / 'rule_catalog.csv').open(encoding='utf-8', newline='') as stream:
        catalog.update({r['rule_id']: r for r in csv.DictReader(stream)})
    write('rule_catalog.csv', list(catalog.values()))
    for name in schemas:
        (target / (name + '.partial.parquet')).replace(target / (name + '.parquet'))
    summary = dict(input_pairs=counts['pairs_summary'], findings=counts['findings'],
                   unmatched_or_review=counts['unmatched_findings'], per_oracle_errors=dict(errors))
    (target / 'run_summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))
    metadata.update(phase='finished', code_unchanged=all(file_sha(ROOT / name) == digest
                                                     for name, digest in fingerprints.items()))
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()

