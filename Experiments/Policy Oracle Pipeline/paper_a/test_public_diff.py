"""Metadata guards for the public comparison reader."""
import unittest
import io
import hashlib
from public_diff import parse_diff,workflow_sections,read_workflow_diff


class DiffTests(unittest.TestCase):
    def test_stream_retains_only_workflow_sections_and_hashes_every_byte(self):
        body=b'diff --git a/tests/data b/tests/data\n--- a/tests/data\n+++ b/tests/data\n@@ -1 +1 @@\n-\x96\n+\x85\n'+b'diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-a\n+b\n'
        response=io.BytesIO(body);response.headers={'Content-Length':str(len(body))}
        text,digest,size=read_workflow_diff(response)
        self.assertEqual(len(body),size)
        self.assertEqual(hashlib.sha256(body).hexdigest(),digest)
        self.assertEqual(['.github/workflows/ci.yml'],[r['filename'] for r in parse_diff(text)])
    def test_non_workflow_encoding_does_not_hide_workflow_metadata(self):
        other=b'diff --git a/tests/binary.fixture b/tests/binary.fixture\n--- a/tests/binary.fixture\n+++ b/tests/binary.fixture\n@@ -1 +1 @@\n-\x96\n+\x85\n'
        workflow=b'diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n@@ -1 +1 @@\n-name: old\n+name: new\n'
        rows=parse_diff(workflow_sections(other+workflow))
        self.assertEqual(['.github/workflows/ci.yml'],[r['filename'] for r in rows])
    def test_added_workflow(self):
        text='diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\nnew file mode 100644\n--- /dev/null\n+++ b/.github/workflows/ci.yml\n@@ -0,0 +1 @@\n+name: CI\n'
        self.assertEqual('added',parse_diff(text)[0]['status'])
    def test_deleted_workflow(self):
        text='diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\ndeleted file mode 100644\n--- a/.github/workflows/ci.yml\n+++ /dev/null\n@@ -1 +0,0 @@\n-name: CI\n'
        row=parse_diff(text)[0]
        self.assertEqual(('removed','.github/workflows/ci.yml'),(row['status'],row['filename']))
    def test_unchanged_content_rename(self):
        text='diff --git a/.github/workflows/a.yml b/.github/workflows/b.yml\nsimilarity index 100%\nrename from .github/workflows/a.yml\nrename to .github/workflows/b.yml\n'
        row=parse_diff(text)[0]
        self.assertEqual(('renamed','.github/workflows/a.yml','.github/workflows/b.yml'),(row['status'],row['previous_filename'],row['filename']))
    def test_quoted_unicode_path(self):
        path='"b/.github/workflows/\\346\\265\\213.yml"'
        text='diff --git "a/.github/workflows/\\346\\265\\213.yml" '+path+'\nnew file mode 100644\n--- /dev/null\n+++ '+path+'\n@@ -0,0 +1 @@\n+name: CI\n'
        self.assertEqual('.github/workflows/测.yml',parse_diff(text)[0]['filename'])
    def test_path_with_spaces(self):
        text='diff --git a/.github/workflows/ci job.yml b/.github/workflows/ci job.yml\n--- a/.github/workflows/ci job.yml\n+++ b/.github/workflows/ci job.yml\n@@ -1 +1 @@\n-a\n+b\n'
        self.assertEqual('.github/workflows/ci job.yml',parse_diff(text)[0]['filename'])
    def test_space_path_with_unified_diff_tab_separator(self):
        text='diff --git a/.github/workflows/ci job.yml b/.github/workflows/ci job.yml\nnew file mode 100644\n--- /dev/null\n+++ b/.github/workflows/ci job.yml\t\n@@ -0,0 +1 @@\n+name: CI\n'
        self.assertEqual('.github/workflows/ci job.yml',parse_diff(text)[0]['filename'])
    def test_html_is_not_an_empty_comparison(self):
        with self.assertRaises(ValueError):parse_diff('<html>Sign in</html>')


if __name__=='__main__':unittest.main()
