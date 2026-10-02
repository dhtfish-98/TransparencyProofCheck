import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from transparency_proof_check import Limits, check_bytes, check_file
from reference_tree import consistency_request, inclusion_request
from test_proofs import evaluate


class ContractTests(unittest.TestCase):
    def test_invalid_json_and_duplicate_keys(self):
        for raw in [b"", b"\xff", b"{} trailing", b"[]", b"null", b"{\"x\":NaN}",
                    b"{\"x\":Infinity}", b"{\"x\":1,\"x\":2}", b"\xef\xbb\xbf{}"]:
            with self.subTest(raw=raw):
                result = check_bytes(raw)
                self.assertEqual(result["status"], "OPEN")
                self.assertFalse(result["complete"])
        duplicate = b'{"schema_version":1,"schema_version":1}'
        self.assertEqual(check_bytes(duplicate)["errors"], ["duplicate_json_key"])

    def test_schema_algorithm_and_unknown_fields(self):
        valid = inclusion_request(0, (b"",))
        for field, value in [("schema_version", True), ("schema_version", 2), ("schema_version", "1"),
                             ("hash_algorithm", "sha512"), ("operation", "subtree"),
                             ("operation", "compact_range"), ("operation", []), ("signature", "fake")]:
            changed = copy.deepcopy(valid)
            changed[field] = value
            self.assertEqual(evaluate(changed)["status"], "OPEN")
        for field in valid:
            changed = copy.deepcopy(valid)
            del changed[field]
            self.assertEqual(evaluate(changed)["status"], "OPEN")
        changed = copy.deepcopy(valid)
        changed["leaf_hash"] = valid["root_hash"]
        self.assertEqual(evaluate(changed)["errors"], ["exactly_one_leaf_form_required"])

    def test_invalid_sizes_indexes_and_tree_decrease(self):
        request = inclusion_request(0, (b"a", b"b"))
        for field in ["leaf_index", "tree_size"]:
            for value in [True, -1, 2.0, "2", 1 << 64, None]:
                changed = copy.deepcopy(request)
                changed[field] = value
                self.assertEqual(evaluate(changed)["status"], "OPEN")
        request["leaf_index"] = 2
        self.assertEqual(evaluate(request)["errors"], ["leaf_index_outside_tree"])
        request = consistency_request(1, (b"a", b"b"))
        for field in ["old_size", "new_size"]:
            for value in [True, -1, 2.0, "2", 1 << 64, None]:
                changed = copy.deepcopy(request)
                changed[field] = value
                self.assertEqual(evaluate(changed)["status"], "OPEN")
        request["old_size"] = 3
        self.assertEqual(evaluate(request)["errors"], ["tree_size_decreased"])

    def test_every_hash_width_checked(self):
        requests = [inclusion_request(0, (b"a", b"b")), consistency_request(1, (b"a", b"b"))]
        for request in requests:
            fields = ["root_hash"] if request["operation"] == "inclusion" else ["old_root", "new_root"]
            for field in fields:
                for value in ["00" * 31, "00" * 33, "gg" * 32, None, 32, "00 " * 32]:
                    changed = copy.deepcopy(request)
                    changed[field] = value
                    self.assertEqual(evaluate(changed)["errors"], ["invalid_sha256_hash"])
            changed = copy.deepcopy(request)
            changed["proof"][0] = "00" * 31
            self.assertEqual(evaluate(changed)["errors"], ["invalid_sha256_hash"])
            changed["proof"] = None
            self.assertEqual(evaluate(changed)["errors"], ["invalid_proof_array"])
        request = inclusion_request(0, (b"a",))
        del request["leaf"]
        request["leaf_hash"] = "00" * 31
        self.assertEqual(evaluate(request)["errors"], ["invalid_sha256_hash"])

    def test_budgets_and_depth_string_scanner(self):
        request = inclusion_request(0, (b"1234",))
        raw = json.dumps(request).encode()
        self.assertEqual(check_bytes(raw, Limits(input_bytes=len(raw)))["status"], "PASS")
        self.assertEqual(check_bytes(raw, Limits(input_bytes=len(raw)))["limits"]["input_bytes"], len(raw))
        self.assertEqual(check_bytes(raw, Limits(input_bytes=len(raw) - 1))["errors"], ["input_byte_budget_exceeded"])
        self.assertEqual(evaluate(request, Limits(leaf_bytes=3))["errors"], ["leaf_byte_budget_exceeded"])
        self.assertEqual(evaluate(request, Limits(leaf_bytes=4))["status"], "PASS")
        request = inclusion_request(0, (b"a", b"b"))
        self.assertEqual(evaluate(request, Limits(proof_nodes=0))["errors"], ["proof_node_budget_exceeded"])
        self.assertEqual(evaluate(request, Limits(proof_nodes=1))["status"], "PASS")
        self.assertEqual(check_bytes(b"[" * 17 + b"0" + b"]" * 17)["errors"], ["json_depth_exceeded"])
        escaped = json.dumps({"x": '[{"\\"' * 50}).encode()
        self.assertNotEqual(check_bytes(escaped, Limits(json_depth=1))["errors"], ["json_depth_exceeded"])
        self.assertEqual(evaluate(inclusion_request(0, (b"",)), Limits(json_depth=1))["errors"], ["json_depth_exceeded"])
        for field, maximum in [("input_bytes", 8388608), ("leaf_bytes", 1048576), ("proof_nodes", 65), ("json_depth", 64)]:
            for value in [True, -1, maximum + 1, "1", 1.0]:
                with self.assertRaises(ValueError):
                    Limits(**{field: value})

    def test_api_types_do_not_silently_default(self):
        for limits in [False, 0, {}, []]:
            with self.assertRaises(TypeError):
                check_bytes(b"{}", limits)
            with self.assertRaises(TypeError):
                check_file("unused", limits)
        for raw in ["{}", bytearray(b"{}"), None]:
            with self.assertRaises(TypeError):
                check_bytes(raw)

    def test_local_reader_rejects_non_regular_and_symlinks(self):
        if os.name != "posix":
            self.skipTest("POSIX reader")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source = root / "proof.json"
            raw = json.dumps(inclusion_request(0, (b"",))).encode()
            source.write_bytes(raw)
            self.assertEqual(check_file(source)["status"], "PASS")
            link = root / "link.json"
            link.symlink_to(source)
            self.assertEqual(check_file(link)["status"], "OPEN")
            directory = root / "actual"
            directory.mkdir()
            (directory / "proof.json").write_bytes(raw)
            linked_parent = root / "alias"
            linked_parent.symlink_to(directory, target_is_directory=True)
            self.assertEqual(check_file(linked_parent / "proof.json")["status"], "OPEN")
            self.assertEqual(check_file(root)["errors"], ["regular_file_required"])
            fifo = root / "fifo"
            os.mkfifo(fifo)
            self.assertEqual(check_file(fifo)["errors"], ["regular_file_required"])
            self.assertEqual(check_file(root / "missing")["status"], "OPEN")
            self.assertEqual(check_file(str(root / "actual") + "/../proof.json")["errors"], ["parent_path_segment_not_supported"])
            self.assertEqual(check_file(str(root / "alias") + "/../proof.json")["errors"], ["parent_path_segment_not_supported"])
            self.assertEqual(check_file(source, Limits(input_bytes=1))["errors"], ["input_byte_budget_exceeded"])
            self.assertEqual(check_file(source, Limits(input_bytes=1))["limits"]["input_bytes"], 1)
            self.assertEqual(source.read_bytes(), raw)

    def test_reader_change_detection_and_invalid_path(self):
        for invalid in [b"path", "", "abc\x00def", None, 123]:
            self.assertEqual(check_file(invalid)["errors"], ["invalid_local_path"])
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp).resolve() / "proof.json"
            raw = json.dumps(inclusion_request(0, (b"",))).encode()
            source.write_bytes(raw)
            original_read = os.read
            changed = False

            def change_on_read(fd, amount):
                nonlocal changed
                data = original_read(fd, amount)
                if not changed:
                    changed = True
                    source.write_bytes(raw + b" ")
                return data

            with mock.patch("transparency_proof_check.input.os.read", side_effect=change_on_read):
                self.assertEqual(check_file(source)["errors"], ["input_changed_during_read"])

    def test_unsupported_safe_reader_stays_open(self):
        with mock.patch("transparency_proof_check.input.os.supports_dir_fd", set()):
            self.assertEqual(check_file("unused")["errors"], ["safe_local_read_unavailable"])

    def test_cli_exit_codes_privacy_and_input_preservation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            requests = [inclusion_request(0, (b"PRIVATE_CLI_TEST_VALUE",))]
            bad = copy.deepcopy(requests[0])
            bad["root_hash"] = "00" * 32
            requests.append(bad)
            requests.append({"schema_version": 77})
            for index, (request, expected) in enumerate(zip(requests, [0, 1, 2], strict=True)):
                source = root / f"input-{index}.json"
                raw = json.dumps(request).encode()
                source.write_bytes(raw)
                env = os.environ.copy()
                process = subprocess.run([sys.executable, "-m", "transparency_proof_check", str(source)],
                                         capture_output=True, env=env, timeout=10)
                self.assertEqual(process.returncode, expected)
                self.assertEqual(process.stderr, b"")
                report = json.loads(process.stdout)
                self.assertEqual(report["status"], ["PASS", "FAIL", "OPEN"][index])
                self.assertNotIn(b"PRIVATE_CLI_TEST_VALUE", process.stdout)
                self.assertNotIn(str(source).encode(), process.stdout)
                self.assertEqual(source.read_bytes(), raw)
            process = subprocess.run([sys.executable, "-m", "transparency_proof_check", str(source),
                                      "--max-proof-nodes", "66"], capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(json.loads(process.stdout)["errors"], ["invalid_limits"])

    def test_cli_argument_errors_are_private_json_open(self):
        for arguments in [[], ["private_inert_path", "--private_unknown"],
                          ["private_inert_path", "--max-input-bytes", "private_non_number"]]:
            process = subprocess.run([sys.executable, "-m", "transparency_proof_check", *arguments],
                                     capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stderr, b"")
            report = json.loads(process.stdout)
            self.assertEqual(report["status"], "OPEN")
            self.assertFalse(report["complete"])
            self.assertEqual(report["errors"], ["invalid_arguments"])
            self.assertEqual(report["root_authenticity"], "OPEN")
            self.assertEqual(report["content_authenticity"], "OPEN")
            self.assertEqual(report["cvp_eligibility"], "OPEN")
            self.assertNotIn(b"private_", process.stdout)
            self.assertNotIn(b"private_", process.stderr)
        help_output = subprocess.run([sys.executable, "-m", "transparency_proof_check", "--help"],
                                     capture_output=True, timeout=10)
        self.assertEqual(help_output.returncode, 0)
        self.assertEqual(help_output.stderr, b"")
        self.assertIn(b"usage:", help_output.stdout)


if __name__ == "__main__":
    unittest.main()
