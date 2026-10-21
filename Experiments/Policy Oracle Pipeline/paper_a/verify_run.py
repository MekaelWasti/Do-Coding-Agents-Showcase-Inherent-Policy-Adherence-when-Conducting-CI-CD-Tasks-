"""Check that a published run accounts for its input and reconciles rule counts."""
import argparse
import collections
import csv
import itertools
import json
from pathlib import Path
import pyarrow.parquet as pq
from run_oracles import file_sha, GROUPS
from paths import OUT

ROOT = Path(__file__).resolve().parent


def rows(path, columns=None):
    for batch in pq.ParquetFile(path).iter_batches(batch_size=512, columns=columns):
        yield from batch.to_pylist()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', default=str(OUT / 'full_run'))
    args = parser.parse_args()
    run = Path(args.run)
    metadata = json.loads((run / 'run_metadata.json').read_text(encoding='utf-8-sig'))
    errors = []
    if metadata['phase'] != 'finished' or not metadata['code_unchanged']:
        errors.append('Run did not finish with unchanged code')
    if file_sha(metadata['input']) != metadata['input_sha256']:
        errors.append('Input hash differs from the recorded run')
    for name, digest in metadata['code_sha256'].items():
        if file_sha(ROOT / name) != digest:
            errors.append('Current source differs: ' + name)
    with (OUT / 'rule_catalog.csv').open(encoding='utf-8-sig', newline='') as stream:
        catalog = {r['rule_id']: r for r in csv.DictReader(stream)}
    for rule in catalog.values():
        if not rule['source'] or not rule['check']:
            errors.append('Rule lacks source/check: ' + rule['rule_id'])
    summary_rows = rows(run / 'pairs_summary.parquet')
    finding_groups = iter(itertools.groupby(rows(run / 'findings.parquet'), lambda r: r['pair_id']))
    next_group = next(finding_groups, None)
    seen = set()
    totals = collections.Counter()
    for pair, summary in itertools.zip_longest(rows(metadata['input'], ['pair_id', 'conversion_status']), summary_rows):
        if pair is None or summary is None:
            errors.append('Input and summary row counts differ')
            break
        pair_id = pair['pair_id']
        if pair_id != summary['pair_id']:
            errors.append('Input and summary order/identity differ at ' + pair_id)
            break
        if pair_id in seen:
            errors.append('Duplicate pair ID: ' + pair_id)
        seen.add(pair_id)
        if pair['conversion_status'] != summary['conversion_status']:
            errors.append('Conversion status differs: ' + pair_id)
        if pair['conversion_status'] == 'ready':
            scan_status = json.loads(summary['scan_status'])
            side_counts = json.loads(summary['side_scan_counts'])
            for oracle in ['zizmor', 'actionlint', 'custom']:
                for side in ['before', 'after']:
                    key = oracle + '_' + side
                    state = scan_status.get(key)
                    if state not in ['analyzed', 'error']:
                        errors.append('Missing side-scan outcome: ' + pair_id + ':' + key)
                    elif state == 'analyzed' and not isinstance(side_counts.get(key), int):
                        errors.append('Missing side-scan count: ' + pair_id + ':' + key)
                    elif state == 'error' and side_counts.get(key) is not None:
                        errors.append('Failed side scan has a count: ' + pair_id + ':' + key)
            for finding in json.loads(summary['partial_findings']):
                if finding['rule_id'] not in catalog:
                    errors.append('Partial observation lacks a rule source: ' + finding['rule_id'])
                elif finding.get('rule_group') != catalog[finding['rule_id']]['rule_group']:
                    errors.append('Partial observation has an inconsistent rule group: ' + finding['rule_id'])
                if any(finding.get(key) != summary[key] for key in ['source', 'repo', 'commit_or_pr']):
                    errors.append('Partial observation has inconsistent pair provenance: ' + pair_id)
                if 'status' in finding:
                    errors.append('Partial observation has an unsupported delta label: ' + pair_id)
                if finding['side'] not in ['before', 'after'] or scan_status.get(finding['oracle']) != 'error':
                    errors.append('Unqualified partial observation: ' + pair_id)
                totals['partial_findings'] += 1
        found = list(next_group[1]) if next_group and next_group[0] == pair_id else []
        if found:
            next_group = next(finding_groups, None)
        counts = collections.Counter()
        for finding in found:
            rule = catalog.get(finding['rule_id'])
            if not rule or rule['rule_group'] != finding['rule_group']:
                errors.append('Missing or inconsistent rule group: ' + finding['rule_id'])
            counts[(finding['rule_group'], finding['status'])] += 1
            totals['findings'] += 1
            totals['unmatched_or_review'] += finding['match_basis'] == 'unmatched' or finding['needs_review']
        observed = {g + ':' + status: n for (g, status), n in counts.items()}
        if observed != json.loads(summary['observed_group_counts']):
            errors.append('Observed counts differ: ' + pair_id)
        for group in GROUPS:
            for status in ['introduced', 'fixed', 'persisted']:
                value = summary[group + '_' + status]
                if value is not None and value != counts[(group, status)]:
                    errors.append('Published count differs: ' + pair_id)
        zizmor = sum(f['oracle'] == 'zizmor' and f['status'] == 'introduced' for f in found)
        if summary['zizmor_status'] == 'analyzed' and summary['zizmor_introduced'] != zizmor:
            errors.append('Zizmor count differs: ' + pair_id)
        totals['input_pairs'] += 1
        totals['pending_pairs'] += summary['conversion_status'] == 'pending'
        totals['excluded_pairs'] += summary['conversion_status'] == 'excluded'
        totals['all_oracles_complete'] += summary['all_oracles_complete']
    if next_group:
        errors.append('Finding rows do not belong to accounted input pairs')
    reported = json.loads((run / 'run_summary.json').read_text())
    for key in ['input_pairs', 'findings', 'unmatched_or_review']:
        if reported[key] != totals[key]:
            errors.append('Run summary differs: ' + key)
    if pq.ParquetFile(run / 'unmatched_findings.parquet').metadata.num_rows != totals['unmatched_or_review']:
        errors.append('Review-log row count differs')
    result = dict(passed=not errors, errors=errors, counts=dict(totals),
                  final_cohort=totals['pending_pairs'] == 0,
                  qualification='Passing validates this snapshot; no pending rows is a separate final-cohort gate.')
    (run / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    if errors:
        raise SystemExit('Output verification failed')


if __name__ == '__main__':
    main()
