"""Historical boundary tests without network calls or date/order guesses."""
import unittest
from unittest.mock import MagicMock,patch
import tempfile
from pathlib import Path
from urllib.error import HTTPError,URLError
import requests
from prefetch_parents import complete_parents
from recover_pairs import commit_boundaries,canonical_paths,raw_bytes,RAW_SESSIONS,recover,workflow_path
from assemble_pairs import comparison_qualification

def commit(*parents): return {'parents':[{'sha':p} for p in parents]}

class HistoryTests(unittest.TestCase):
    def test_capped_comparison_without_full_audit_is_qualified(self):
        record=dict(pr_id=1,base_sha='base',head_sha='head',comparison_may_be_truncated=True)
        self.assertIsNotNone(comparison_qualification(record,set()))
    def test_full_metadata_audit_must_match_exact_snapshot(self):
        record=dict(pr_id=1,base_sha='base',head_sha='head',comparison_may_be_truncated=True)
        self.assertIsNone(comparison_qualification(record,{(1,'base','head')}))
        self.assertIsNotNone(comparison_qualification(record,{(1,'base','different-head')}))
    def test_uncapped_comparison_does_not_receive_cap_warning(self):
        record=dict(pr_id=1,base_sha='base',head_sha='head',comparison_may_be_truncated=False)
        self.assertIsNone(comparison_qualification(record,set()))
    def test_identical_content_rename_remains_a_workflow_pair(self):
        old='.github/workflows/old.yml';new='.github/workflows/new.yml'
        pr=dict(id=1,repo='example/repo',number=1,agent='OpenAI_Codex',stars=123,state='closed',created_at=None,closed_at=None,merged_at=None)
        comparison=dict(status='ok',source='GitHub_public_comparison_diff',url='https://example.test/diff',sha256='test',files=[dict(filename=new,status='renamed',previous_filename=old)])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch('recover_pairs.RESULTS',root),patch('recover_pairs.CACHE',root),patch('recover_pairs.parent_path',return_value=root/'missing.json'),patch('recover_pairs.gh',return_value=dict(status='ok',response=[[dict(sha='head',parents=[dict(sha='base')])]])),patch('recover_pairs.public_comparison',return_value=comparison),patch('recover_pairs.raw',return_value=dict(status='found',text='name: CI\n')):
                result=recover(pr,{'head'},{old,new})
        self.assertEqual(1,len(result['pairs']))
        pair=result['pairs'][0]
        self.assertEqual(('renamed',old,new),(pair['change_type'],pair['before_path'],pair['after_path']))
        self.assertEqual(pair['before_yaml'],pair['after_yaml'])
    def test_rename_to_disabled_file_keeps_old_workflow_state(self):
        old='.github/workflows/check.yaml';new=old+'_disabled'
        metadata=[dict(filename=new,status='renamed',previous_filename=old)]
        self.assertEqual([old],[p for p in canonical_paths({new},metadata) if workflow_path(p)])
    def test_reused_rename_targets_are_not_suppressed(self):
        a='.github/workflows/a.yml';b='.github/workflows/b.yml'
        metadata=[dict(filename=a,status='renamed',previous_filename=b),dict(filename=b,status='renamed',previous_filename=a)]
        self.assertEqual([a,b],canonical_paths({a,b},metadata))
    def test_transport_preserves_bytes_without_text_decoding(self):
        session=MagicMock();response=session.get.return_value.__enter__.return_value
        response.status_code=200;response.content=b'\xef\xbb\xbfname: CI\r\n'
        with unittest.mock.patch.object(RAW_SESSIONS,'session',session,create=True):
            self.assertEqual(response.content,raw_bytes('https://example.test/file'))
    def test_transport_404_retains_authenticated_fallback_signal(self):
        session=MagicMock();response=session.get.return_value.__enter__.return_value
        response.status_code=404;response.reason='Not Found';response.headers={}
        with unittest.mock.patch.object(RAW_SESSIONS,'session',session,create=True):
            with self.assertRaises(HTTPError) as caught:raw_bytes('https://example.test/file')
        self.assertEqual(404,caught.exception.code)
    def test_transport_timeout_retains_retry_signal(self):
        session=MagicMock();session.get.side_effect=requests.Timeout('read timed out')
        with unittest.mock.patch.object(RAW_SESSIONS,'session',session,create=True):
            with self.assertRaises(URLError):raw_bytes('https://example.test/file')
    def test_parent_cache_rejects_a_different_oid(self):
        node=dict(oid='other',parents=dict(nodes=[dict(oid='base')],pageInfo=dict(hasNextPage=False)))
        self.assertIsNone(complete_parents(node,'wanted'))
    def test_parent_cache_rejects_a_truncated_connection(self):
        node=dict(oid='head',parents=dict(nodes=[dict(oid='base')],pageInfo=dict(hasNextPage=True)))
        self.assertIsNone(complete_parents(node,'head'))
    def test_parent_cache_does_not_treat_missing_parents_as_a_root(self):
        self.assertIsNone(complete_parents(dict(oid='head'),'head'))
    def test_parent_and_terminal_sha_do_not_depend_on_list_order(self):
        graph={'second':commit('first'),'first':commit('base')}
        self.assertEqual(('base','second','first'),commit_boundaries(set(graph),graph))
    def test_merge_uses_actual_first_parent(self):
        graph={'first':commit('base','another-base'),'head':commit('first','outside')}
        self.assertEqual(('base','head','first'),commit_boundaries(set(graph),graph))
    def test_single_commit(self):
        graph={'head':commit('base')}
        self.assertEqual(('base','head','head'),commit_boundaries(set(graph),graph))
    def test_missing_source_commit_is_not_guessed(self):
        with self.assertRaises(ValueError): commit_boundaries({'first','head'},{'first':commit('base')})
    def test_two_roots_are_explicitly_ambiguous(self):
        graph={'a':commit('base'),'b':commit('other'),'head':commit('a','b')}
        with self.assertRaises(ValueError): commit_boundaries(set(graph),graph)
    def test_multiple_heads_are_not_arbitrarily_sorted(self):
        graph={'first':commit('base'),'a':commit('first'),'b':commit('first')}
        with self.assertRaises(ValueError): commit_boundaries(set(graph),graph)
    def test_parentless_commit_is_explicit(self):
        with self.assertRaises(ValueError): commit_boundaries({'root'},{'root':commit()})
    def test_rename_old_path_sorts_first(self):
        files={'.github/workflows/a.yml','.github/workflows/z.yml'}
        meta=[dict(status='renamed',previous_filename='.github/workflows/a.yml',filename='.github/workflows/z.yml')]
        self.assertEqual(['.github/workflows/z.yml'],canonical_paths(files,meta))
    def test_rename_new_path_sorts_first(self):
        files={'.github/workflows/a.yml','.github/workflows/z.yml'}
        meta=[dict(status='renamed',previous_filename='.github/workflows/z.yml',filename='.github/workflows/a.yml')]
        self.assertEqual(['.github/workflows/a.yml'],canonical_paths(files,meta))
    def test_unrelated_old_path_is_not_removed(self):
        files={'.github/workflows/a.yml','.github/workflows/z.yml'}
        meta=[dict(status='renamed',previous_filename='outside.yml',filename='.github/workflows/z.yml')]
        self.assertEqual(sorted(files),canonical_paths(files,meta))

if __name__=='__main__': unittest.main(verbosity=2)
