"""Synthetic regression tests for exact worktree/index/history secret checks."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ExactKeyCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        shutil.copyfile(Path(__file__).with_name('verify-key-absence.py'), self.root / 'scripts/verify-key-absence.py')
        self.key = 'synthetic-' + 'A' * 32
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Offline fixture')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL)

    def verify(self):
        env = os.environ.copy()
        env['LMIST_LLM_APIKEY'] = self.key
        run = subprocess.run([os.sys.executable, '-B', str(self.root / 'scripts/verify-key-absence.py')],
                             env=env, capture_output=True, text=True)
        self.assertNotIn(self.key, run.stdout + run.stderr)
        return run.returncode, json.loads(run.stdout)

    def test_absent_in_empty_repo(self):
        code, result = self.verify()
        self.assertEqual(0, code)
        self.assertEqual('ABSENT', result['localGitHistoryAndObjects'])

    def test_ignored_file_is_not_skipped(self):
        (self.root / '.gitignore').write_text('.env\n')
        (self.root / '.env').write_text(self.key)
        code, result = self.verify()
        self.assertEqual(1, code)
        self.assertEqual('FOUND', result['workingTree'])

    def test_clean_worktree_does_not_hide_staged_key(self):
        (self.root / 'fixture.txt').write_text(self.key)
        self.git('add', 'fixture.txt')
        (self.root / 'fixture.txt').write_text('clean')
        code, result = self.verify()
        self.assertEqual(1, code)
        self.assertEqual('ABSENT', result['workingTree'])
        self.assertEqual('FOUND', result['index'])

    def test_binary_file_is_not_skipped_after_null_bytes(self):
        (self.root / 'fixture.db').write_bytes(b'\x00' * 65536 + self.key.encode())
        code, result = self.verify()
        self.assertEqual(1, code)
        self.assertEqual('FOUND', result['workingTree'])

    def test_git_metadata_is_also_checked(self):
        # Metadata is not part of cat-file --batch-all-objects.
        (self.root / '.git' / 'fixture-secret').write_text(self.key)
        code, result = self.verify()
        self.assertEqual(1, code)
        self.assertEqual('FOUND', result['workingTree'])

    def test_history_is_checked_across_read_chunk_boundary(self):
        (self.root / 'fixture.txt').write_text('X' * 65530 + self.key)
        self.git('add', 'fixture.txt')
        self.git('commit', '-qm', 'synthetic historical fixture')
        (self.root / 'fixture.txt').write_text('clean')
        self.git('add', 'fixture.txt')
        self.git('commit', '-qm', 'remove synthetic fixture')
        code, result = self.verify()
        self.assertEqual(1, code)
        self.assertEqual('ABSENT', result['workingTree'])
        self.assertEqual('ABSENT', result['index'])
        self.assertEqual('FOUND', result['localGitHistoryAndObjects'])


if __name__ == '__main__':
    unittest.main()
