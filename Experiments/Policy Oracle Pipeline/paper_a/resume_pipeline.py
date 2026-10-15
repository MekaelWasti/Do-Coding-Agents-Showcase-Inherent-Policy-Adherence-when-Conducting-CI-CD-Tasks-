"""Resume recovery, then assemble, scan, and verify the complete cohort.

Each existing stage keeps its own caches. Logs and stage status survive a
disconnected tool session. Stop on the first failed stage; never publish success
from an unfinished recovery or failed verification.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
from paths import OUT


def main():
    names = ['recover', 'comparison_audit', 'export', 'assemble', 'scan', 'verify', 'regression']
    parser = argparse.ArgumentParser()
    parser.add_argument('--from-stage', choices=names, default='recover')
    args = parser.parse_args()
    status = {'pid': os.getpid(), 'phase': 'running', 'stages': []}
    start = names.index(args.from_stage)
    if start:
        previous = json.loads((OUT / 'pipeline_status.json').read_text(encoding='utf-8'))
        completed = {stage['name']: stage for stage in previous['stages']}
        for name in names[:start]:
            stage = completed.get(name, {})
            if stage.get('phase') != 'finished' or stage.get('exit_code') != 0:
                raise SystemExit('Cannot skip an unfinished stage: ' + name)
            status['stages'].append(dict(stage, completed_in_previous_run=True))
        (OUT / 'pipeline_status.previous.json').write_text(json.dumps(previous, indent=2), encoding='utf-8')
        status['resumed_from'] = args.from_stage
    def save():
        status['updated_at'] = datetime.now(timezone.utc).isoformat()
        temporary = OUT / 'pipeline_status.tmp'
        temporary.write_text(json.dumps(status, indent=2), encoding='utf-8')
        temporary.replace(OUT / 'pipeline_status.json')

    commands = [
        ('recover', [str(ROOT / 'recover_pairs.py')]),
        ('comparison_audit', [str(ROOT / 'audit_comparisons.py')]),
        ('export', ['-c', 'from recover_pairs import export; export()']),
        ('assemble', [str(ROOT / 'assemble_pairs.py')]),
        ('scan', [str(ROOT / 'run_oracles.py'), '--input', str(OUT / 'pairs.parquet'),
                  '--output', str(OUT / 'full_run')]),
        ('verify', [str(ROOT / 'verify_run.py')]),
        ('regression', [str(ROOT / 'regression.py')]),
    ]
    save()
    for name, arguments in commands[start:]:
        stage = {'name': name, 'phase': 'running', 'log': str(OUT / (name + '.log'))}
        status['stages'].append(stage)
        save()
        with open(stage['log'], 'a', encoding='utf-8') as log:
            log.write('\nResume: ' + datetime.now(timezone.utc).isoformat() + '\n')
            log.flush()
            code = subprocess.call([sys.executable, '-u', *arguments], cwd=ROOT,
                                   stdout=log, stderr=subprocess.STDOUT)
        stage.update(phase='finished' if code == 0 else 'failed', exit_code=code)
        if code != 0:
            status['phase'] = 'failed'
            save()
            raise SystemExit(code)
        if name == 'assemble':
            counts = json.loads((OUT / 'assembly_counts.json').read_text())
            if not counts['full_recovery_processed'] or counts['pending_prs']:
                status['phase'] = 'failed_incomplete_recovery'
                save()
                raise SystemExit('Assembly still contains pending PRs')
        save()
    status['phase'] = 'finished_requires_final_audit'
    save()


if __name__ == '__main__':
    main()
