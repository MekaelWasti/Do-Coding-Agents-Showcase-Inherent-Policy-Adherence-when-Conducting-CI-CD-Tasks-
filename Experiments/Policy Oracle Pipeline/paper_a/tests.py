"""Behavior checks: movement, renames, scope, errors, and real tool outputs."""
import unittest
import json
from dataclasses import asdict
from unittest.mock import patch
from oracles import analyze
from oracles import Finding,check,change_flags,compare_findings
from run_oracles import normalize

def workflow(steps,permissions='contents: read',job='build'):
    permission_block='\npermissions:\n  '+permissions.replace('\n','\n  ') if permissions is not None else ''
    return 'name: CI\non: push'+permission_block+'\njobs:\n  '+job+':\n    runs-on: ubuntu-latest\n    steps:\n'+steps

class Tests(unittest.TestCase):
    def test_duplicate_evidence_after_job_renames_requires_review(self):
        old=workflow('      - uses: actions/checkout@v4\n',job='old_one')+'  old_two:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n'
        new=old.replace('old_one:','new_one:').replace('old_two:','new_two:')
        before=[Finding('zizmor','Z_unpinned_uses','high',f'jobs.{job}.steps[checkout]','unpinned',job=job,step='checkout',evidence='actions/checkout@v4') for job in ['old_one','old_two']]
        after=[Finding(**dict(f.__dict__,job=job,anchor=f'jobs.{job}.steps[checkout]')) for f,job in zip(before,['new_one','new_two'])]
        rows=compare_findings(before,after,dict(pair_id='renames',before_yaml=old,after_yaml=new,before_exists=True,after_exists=True))
        self.assertEqual(['persisted','persisted'],[row['status'] for row in rows])
        self.assertTrue(all(row['needs_review'] for row in rows))
    def test_partial_actionlint_observation_has_source_without_delta(self):
        partial=dict(side='before',**asdict(Finding('actionlint','A_expression','error','workflow','undefined context')))
        result=dict(statuses={'zizmor':'analyzed','actionlint':'error','custom':'analyzed','change':'analyzed'},
                    errors={'actionlint':'after scan failed'},context_gaps=[],partial_findings=[partial])
        catalog={}
        summary=normalize(dict(source='swechat',repo='example/repo',commit_or_pr='sha'),result,[],catalog)
        self.assertIn('A_expression',catalog)
        self.assertTrue(catalog['A_expression']['source'])
        self.assertTrue(catalog['A_expression']['check'])
        observed=json.loads(summary['partial_findings'])[0]
        self.assertEqual('workflow_correctness',observed['rule_group'])
        self.assertNotIn('status',observed)
        self.assertIsNone(summary['workflow_correctness_introduced'])
        self.assertEqual({},json.loads(summary['observed_group_counts']))
    def test_actionlint_embedded_coordinates_are_not_identity(self):
        old='name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo one\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo two\n'
        new='# moved\n'+old
        context=dict(oracle='actionlint',path='.github/workflows/ci.yml')
        before=check(old,context);after=check(new,context)
        pair=dict(pair_id='coordinate',before_yaml=old,after_yaml=new,before_exists=True,after_exists=True)
        result=compare_findings(before,after,pair)
        self.assertTrue(result)
        self.assertTrue(all(r['status']=='persisted' for r in result))
        self.assertNotEqual(before[0].line,after[0].line)
    def test_after_is_scanned_when_before_fails(self):
        old=workflow('      - run: echo before\n')
        new=workflow('      - run: echo after\n')
        pair=dict(pair_id='partial',before_yaml=old,after_yaml=new,before_exists=True,after_exists=True,
            before_path='.github/workflows/ci.yml',after_path='.github/workflows/ci.yml',conversion_status='ready')
        finding=Finding('zizmor','Z_unpinned_uses','high','workflow','observed after')
        def checker(text,context):
            if context['oracle']=='zizmor' and text==old: raise ValueError('bad before')
            return [finding] if context['oracle']=='zizmor' else []
        with patch('oracles.check',side_effect=checker) as mocked:
            result,delta=analyze(pair)
        self.assertEqual(6,mocked.call_count)
        self.assertEqual('error',result['statuses']['zizmor_before'])
        self.assertEqual('analyzed',result['statuses']['zizmor_after'])
        self.assertEqual(1,result['side_scan_counts']['zizmor_after'])
        self.assertEqual('after',result['partial_findings'][0]['side'])
        self.assertFalse(any(f['oracle']=='zizmor' for f in delta))
    def test_missing_is_error(self):
        with self.assertRaises(ValueError): check(None,dict(oracle='zizmor',path='.github/workflows/ci.yml'))
    def test_real_actionlint_error(self):
        text=workflow('      - run: echo hi\n')+'    needs: missing-job\n'
        findings=check(text,dict(oracle='actionlint',path='.github/workflows/ci.yml'))
        self.assertTrue(findings)
        self.assertTrue(any('missing-job' in f.detail for f in findings))
    def test_reuses_literal_rules(self):
        findings=check(workflow('      - run: echo hi\n'),dict(oracle='custom',path='.github/workflows/ci.yml'))
        self.assertIn('R9_job_timeouts',{f.rule_id for f in findings})
        self.assertNotIn('R1_permissions_declared',{f.rule_id for f in findings})
    def test_new_write_privilege(self):
        old=workflow('      - run: echo hi\n'); new=workflow('      - run: echo hi\n',permissions='contents: write')
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertTrue(any(f.rule_id=='D_permissions_broadened' for f in findings))
    def test_inheritance_does_not_broaden(self):
        old=workflow('      - run: echo hi\n',permissions='contents: write')
        new=old+'    permissions:\n      contents: write\n'
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertFalse(any(f.rule_id=='D_permissions_broadened' for f in findings))
    def test_unknown_defaults_are_not_none(self):
        old=workflow('      - run: echo hi\n',permissions=None)
        new=workflow('      - run: echo hi\n',permissions='contents: write')
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertTrue(gaps)
        self.assertFalse(any(f.rule_id=='D_permissions_broadened' for f in findings))
    def test_removed_test(self):
        old=workflow('      - name: Tests\n        run: pytest\n      - run: echo hi\n')
        new=workflow('      - run: echo hi\n')
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertTrue(any(f.rule_id=='D_test_or_lint_step_removed' for f in findings))
    def test_test_rename_keeps_coverage(self):
        old=workflow('      - name: Tests\n        run: pytest\n')
        new=workflow('      - name: Unit tests\n        run: pytest\n')
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertFalse(any(f.rule_id=='D_test_or_lint_step_removed' for f in findings))
    def test_new_continue_on_error(self):
        old=workflow('      - name: Tests\n        run: pytest\n')
        new=workflow('      - name: Tests\n        run: pytest\n        continue-on-error: true\n')
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertTrue(any(f.rule_id=='D_continue_on_error_added' for f in findings))
    def test_line_movement_persists(self):
        old=Finding('zizmor','Z_unpinned_uses','high','jobs.build.steps[uses:actions/checkout]','unpinned',job='build',step='uses:actions/checkout',evidence='actions/checkout@v4',line=5)
        new=Finding(**dict(old.__dict__,line=18))
        pair=dict(pair_id='case',before_yaml=workflow('      - uses: actions/checkout@v4\n'),after_yaml=workflow('      - run: echo hi\n      - uses: actions/checkout@v4\n'),before_exists=True,after_exists=True)
        rows=compare_findings([old],[new],pair)
        self.assertEqual(['persisted'],[r['status'] for r in rows])
    def test_duplicate_anchors_are_reviewed(self):
        f=Finding('zizmor','Z_unpinned_uses','high','workflow','unpinned',evidence='action@v4')
        pair=dict(pair_id='case',before_yaml=workflow('      - run: echo hi\n'),after_yaml=workflow('      - run: echo hi\n'),before_exists=True,after_exists=True)
        rows=compare_findings([f,f],[f],pair)
        self.assertEqual(1,sum(r['status']=='fixed' for r in rows))
        self.assertTrue(all(r['needs_review'] for r in rows))
    def test_removing_platform_job_is_not_replaced_by_other_platform(self):
        old=workflow('      - name: Tests\n        run: pytest\n')+'  windows:\n    runs-on: windows-latest\n    steps:\n      - name: Tests\n        run: pytest\n'
        new=workflow('      - name: Tests\n        run: pytest\n')
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertTrue(any(f.rule_id=='D_test_or_lint_step_removed' for f in findings))
    def test_identical_job_rename_is_not_step_removal(self):
        old=workflow('      - name: Tests\n        run: pytest\n',job='old')
        new=workflow('      - name: Tests\n        run: pytest\n',job='new')
        findings,gaps=change_flags(old,new,dict(before_exists=True,after_exists=True))
        self.assertFalse(any(f.rule_id=='D_test_or_lint_step_removed' for f in findings))

if __name__=='__main__': unittest.main(verbosity=2)
