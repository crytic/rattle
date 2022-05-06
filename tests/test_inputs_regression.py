""" Uses the rattle/inputs/... files for regression testing
    - expected output in rattle/tests/expected/...
    - expects current directory to be rattle/tests
"""
import logging
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import mkdtemp
from typing import List, Callable

import rattle

logger = logging.getLogger(__name__)


class TestInputRegression(unittest.TestCase):
    INPUTS_DIR_RELATIVE_TO_THIS = '../inputs'
    EXPECTED_DIR_RELATIVE_TO_THIS = 'expected'

    def setUp(self):
        # get the used directories
        self.tests_path = Path(__file__).parent
        self.inputs_path = self.tests_path / self.INPUTS_DIR_RELATIVE_TO_THIS
        self.expected_path = self.tests_path / self.EXPECTED_DIR_RELATIVE_TO_THIS
        self.maxDiff = 10000

    # @unittest.skip
    def test_debug_examples_subset(self):
        """ run only selected tests and write actual output to file for debugging
            - usually skipped
        """
        test_files = ['Lottery.bin'] # ['0x37eb3cb268a0dd1bc2c383296fe34f58c5b5db8b.bin']     # .bin file names w/o path

        self._test_example_group(file_path_filter=lambda path: any(t == path.name for t in test_files),
                                 save_actual_output=True)

    def test_all_examples_in_inputs(self):
        """ run all examples, this is THE regression test method
        """
        self._test_example_group(file_path_filter=lambda _: True)

    def _test_example_group(self, file_path_filter: Callable, save_actual_output=False):
        for bin_file in self.inputs_path.glob('*/*.bin'):
            if file_path_filter(bin_file):
                with self.subTest(bin_file.name):
                    self._single_test(bin_file, save_actual_output)

    def _single_test(self, bin_file: Path, save_actual_output=False):
        """ run rattle on given file and compare actual stdout output (ssa listing) with expected output
        """
        actual_lines = self._run_rattle(bin_file)
        expected_file = (self.expected_path / bin_file.stem).with_suffix('.expected-ssa.lst')

        # no expected file, create it
        if not expected_file.exists():
            with expected_file.open('wt') as f:
                f.writelines(actual_lines)
            logger.warning(f"Expected ssa file .../{self.EXPECTED_DIR_RELATIVE_TO_THIS}/{expected_file.name} "
                           f"does not exist, created!")

        # read expected file
        with expected_file.open('rt') as f:
            expected_lines = f.readlines()

        # write actual lines to <expected_file w/o extension>.actual-ssa.lst file for debugging
        if save_actual_output:
            actual_file = (self.expected_path / bin_file.stem).with_suffix('.actual-ssa.lst')
            with actual_file.open('wt') as f:
                f.writelines(actual_lines)

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
            rattle.main([sys.argv[0],
                         '--input', str(bin_file),
                         '--optimize',
                         '--stdout_to', stdout_file_name,
                         # '--verbosity', 'DEBUG'
                         ])

            with open(stdout_file_name, 'rt') as f:
                output = f.readlines()

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            sys.stdout = orig_stdout

        return output
