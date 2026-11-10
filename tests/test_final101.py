#!/usr/bin/env python3
"""Independent negative controls for final101's acceptance receipt validator.

The positive fixture is an actual sealed eight-cell paired concurrency receipt.
Every negative starts with that accepted baseline and mutates one requirement;
no fabricated receipt is allowed to stand in for the positive control.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ARGS = None
DRIVER = None
BASE = None


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ReceiptControls(unittest.TestCase):
    def validate(self, data):
        return DRIVER.validate_receipt('concurrency', data, ARGS.shared_root, ARGS.core_root)

    def baseline(self):
        data = copy.deepcopy(BASE)
        summary = self.validate(data)
        self.assertIs(summary['passed'], True)
        self.assertEqual(summary['name'], 'concurrency')
        self.assertEqual(summary['native_execution_count'], 8)
        self.assertEqual(len(summary['cell_names']), 8)
        self.assertEqual(set(summary['sanitizers']), {'address', 'thread'})
        return data

    def rejects(self, data):
        # Baseline is validated immediately before each mutation in every test.
        # A nonempty diagnostic and the dedicated error distinguish a rejected
        # requirement from unrelated Python errors or malformed fixture setup.
        with self.assertRaises(DRIVER.ValidationError) as caught:
            self.validate(data)
        self.assertTrue(str(caught.exception).strip())
        return str(caught.exception)

    def test_required_catalog_retains_all_nine_acceptance_gates(self):
        # Counts come from the committed acceptance streams, independently of
        # the driver's iteration. Dropping a runner must not silently shrink
        # what the final gate calls complete.
        expected = {'foundations': 0, 'actor': 48, 'client': 12,
                    'consumer': 0, 'redirect': 122, 'pool': 56,
                    'cancel': 160, 'concurrency': 8, 'failure': 116}
        self.assertEqual(set(DRIVER.SPECS), set(expected))
        self.assertEqual({name: spec['native_count'] for name, spec in DRIVER.SPECS.items()}, expected)
        self.assertEqual({name: spec['units'] for name, spec in DRIVER.SPECS.items() if 'units' in spec},
                         {'foundations': 18, 'client': 6, 'redirect': 2, 'concurrency': 2, 'failure': 3})
        self.assertEqual(DRIVER.SPECS['consumer']['executions'], 2)

    def test_actual_paired_receipt_is_accepted(self):
        self.baseline()

    def test_failed_receipt_is_not_overridden_by_complete_cells(self):
        data = self.baseline(); data['passed'] = False
        self.rejects(data)

    def test_failed_required_cell_is_not_overridden_by_receipt_pass(self):
        data = self.baseline(); data['cells'][0]['passed'] = False
        self.rejects(data)

    def test_missing_cell_fails_even_with_original_advertised_count(self):
        data = self.baseline(); data['cells'].pop()
        self.rejects(data)

    def test_duplicate_cell_fails_with_unchanged_total_count(self):
        data = self.baseline(); data['cells'][1] = copy.deepcopy(data['cells'][0])
        self.rejects(data)

    def test_unknown_cell_cannot_replace_one_required_cell(self):
        data = self.baseline(); data['cells'][0]['name'] = 'address-tcp-unverified'
        self.rejects(data)

    def test_one_sanitizer_cannot_self_report_as_a_smaller_complete_matrix(self):
        data = self.baseline()
        data['cells'] = [c for c in data['cells'] if c['name'].startswith('address-')]
        data['native_execution_count'] = 4
        self.rejects(data)

    def test_explicit_skipped_evidence_fails(self):
        data = self.baseline(); data['skipped'] = ['thread-tls-shutdown']
        self.rejects(data)

    def test_erasing_required_provenance_maps_cannot_disable_validation(self):
        for fields in (
            ('source_sources_before', 'source_sources_after', 'copied_sources_before', 'copied_sources_after'),
            ('core_sources_before', 'core_sources_after'),
            ('artifact_hashes', 'artifact_hashes_after'),
        ):
            with self.subTest(fields=fields):
                data = self.baseline()
                for field in fields:
                    data[field] = {}
                self.rejects(data)

    def test_stale_live_shared_source_fails_even_when_snapshot_maps_agree(self):
        data = self.baseline()
        name = next(k for k in data['source_sources_before'] if k.endswith('surf/async/client.odin'))
        for field in ('source_sources_before', 'source_sources_after', 'copied_sources_before', 'copied_sources_after'):
            data[field][name] = '0' * 64
        self.rejects(data)

    def test_stale_core_fails_even_when_before_after_agree(self):
        data = self.baseline(); name = next(iter(data['core_sources_before']))
        data['core_sources_before'][name] = data['core_sources_after'][name] = '0' * 64
        self.rejects(data)

    def test_stale_binary_fails_even_when_before_after_agree(self):
        data = self.baseline(); name = next(k for k in data['artifact_hashes'] if k.endswith('native-address'))
        data['artifact_hashes'][name] = data['artifact_hashes_after'][name] = '0' * 64
        self.rejects(data)

    def test_physical_copy_mismatch_fails_despite_unchanged_source(self):
        data = self.baseline(); name = next(iter(data['copied_sources_before']))
        data['copied_sources_before'][name] = data['copied_sources_after'][name] = '0' * 64
        self.rejects(data)

    def test_stale_fixture_fails_even_when_before_after_agree(self):
        data = self.baseline(); name = 'tests/testdata/concurrency101/main.odin'
        data['fixtures_before'][name] = data['fixtures_after'][name] = '0' * 64
        self.rejects(data)

    def test_missing_artifact_cannot_be_ignored(self):
        data = self.baseline(); name = next(k for k in data['artifact_hashes'] if k.endswith('native-thread'))
        value = data['artifact_hashes'].pop(name); data['artifact_hashes_after'].pop(name)
        impossible = str(ARGS.receipt.parent / 'missing-required-native-thread')
        self.assertFalse(Path(impossible).exists())
        data['artifact_hashes'][impossible] = data['artifact_hashes_after'][impossible] = value
        self.rejects(data)

    def test_failed_required_command_fails_despite_passed_receipt(self):
        data = self.baseline()
        command = next(c for c in data['commands'] if c['name'] == 'unit-address')
        command['returncode'] = 1
        self.rejects(data)

    def test_stale_execution_log_fails(self):
        data = self.baseline()
        command = next(c for c in data['commands'] if c['name'] == 'unit-thread')
        command['log_sha256'] = '0' * 64
        data['log_hashes'][command['log']] = '0' * 64
        self.rejects(data)

    def test_wrong_unit_layer_count_fails_with_valid_log_hash(self):
        data = self.baseline()
        command = next(c for c in data['commands'] if c['name'] == 'unit-address')
        original = Path(command['log']).read_text()
        self.assertEqual(re.findall(r'Finished (\d+) tests? in ', original), ['2'])
        changed = original.replace('Finished 2 tests in ', 'Finished 1 tests in ')
        self.assertNotEqual(original, changed)
        with tempfile.TemporaryDirectory(prefix='final101-negative-layer-') as tmp:
            log = Path(tmp) / 'unit-address.log'; log.write_text(changed)
            del data['log_hashes'][command['log']]
            command['log'] = str(log); command['log_sha256'] = sha(log)
            data['log_hashes'][str(log)] = sha(log)
            self.rejects(data)


def main():
    global ARGS, DRIVER, BASE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--shared-root', type=Path, required=True)
    parser.add_argument('--core-root', type=Path, required=True)
    ARGS, rest = parser.parse_known_args()
    for name in ('runner', 'receipt', 'shared_root', 'core_root'):
        setattr(ARGS, name, getattr(ARGS, name).resolve())
    spec = importlib.util.spec_from_file_location('independently_reviewed_final101', ARGS.runner)
    DRIVER = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = DRIVER
    spec.loader.exec_module(DRIVER)
    if not issubclass(DRIVER.ValidationError, RuntimeError):
        raise RuntimeError('Dedicated ValidationError ABI changed')
    BASE = json.loads(ARGS.receipt.read_text())
    if len(BASE.get('cells', [])) != 8 or BASE.get('passed') is not True:
        raise RuntimeError('Positive fixture must be actual successful eight-cell receipt')
    unittest.main(argv=[__file__, *rest])


if __name__ == '__main__':
    main()
