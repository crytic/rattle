""" Uses the rattle/inputs/... files for regression testing
    - expected output in rattle/tests/expected/...
    - expects current directory to be rattle/tests
"""
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import mkdtemp
from typing import List

import rattle


class TestInputRegression(unittest.TestCase):

    def setUp(self):
        # get the used directories
        self.tests_path = Path(__file__).parent
        self.inputs_path = self.tests_path / '../inputs'
        self.expected_path = self.tests_path / 'expected'

    def test_something(self):
        self._single_test(self.inputs_path / 'slither_ssa_examples/free_looping.bin')

    def _single_test(self, bin_file: Path):
        """ run rattle on given file and compare stdout output (ssa listing) with expected output
        """
        actual_lines = self._run_rattle(bin_file)
        expected_file = (self.expected_path / bin_file.stem).with_suffix('.expected-ssa.lst')

        # no expected file, create it
        if not expected_file.exists():
            with expected_file.open("wt") as f:
                f.writelines(actual_lines)

        # read expected file
        with expected_file.open("rt") as f:
            expected_lines = f.readlines()

        self.assertListEqual(expected_lines, actual_lines,
                             "\nExpected ssa (first line) and actual ssa differs (second line)")

    @staticmethod
    def _run_rattle(bin_file: Path) -> List[str]:
        """ run rattle.main() for bin_file and returns stdout text
        """
        orig_stdout = sys.stdout
        temp_dir = mkdtemp()

        try:
            stdout_file_name = f'{temp_dir}/rattle.stdout.txt'
            rattle.main([sys.argv[0], '--input', str(bin_file), '-O', '--stdout_to', stdout_file_name])

            with open(stdout_file_name, 'rt') as f:
                output = f.readlines()

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.stdout = orig_stdout

        return output
