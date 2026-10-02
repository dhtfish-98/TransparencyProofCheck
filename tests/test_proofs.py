import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest

from transparency_proof_check import Limits, check_bytes
from transparency_proof_check import proof
from reference_tree import consistency_request, inclusion_request, tree


def evaluate(request: dict, limits: Limits | None = None) -> dict:
    return check_bytes(json.dumps(request, sort_keys=True).encode(), limits)


class ProofTests(unittest.TestCase):
    def test_domain_separated_fixed_hashes(self):
        self.assertEqual(proof.empty_root().hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(proof.leaf_digest(b"").hex(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        self.assertEqual(proof.leaf_digest(b"L123456").hex(), "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56")
        self.assertNotEqual(proof.empty_root(), proof.leaf_digest(b""))

    def test_all_leaf_paths_for_sizes_one_through_64(self):
        count = 0
        for size in range(1, 65):
            items = tuple(f"independent-leaf-{i}".encode() for i in range(size))
            for index in range(size):
                with self.subTest(size=size, index=index):
                    request = inclusion_request(index, items)
                    result = evaluate(request)
                    self.assertEqual(result["status"], "PASS")
                    self.assertEqual(result["calculated_root"], tree(items).hex())
                    self.assertEqual(result["root_authenticity"], "OPEN")
                    self.assertEqual(result["content_authenticity"], "OPEN")
                    h = (index ^ (size - 1)).bit_length()
                    self.assertEqual(len(request["proof"]), h + (index >> h).bit_count())
                    count += 1
        self.assertEqual(count, 2080)

    def test_all_positive_prefixes_for_sizes_one_through_64(self):
        count = 0
        for size in range(1, 65):
            items = tuple(f"prefix-check-{i}".encode() for i in range(size))
            for prefix in range(1, size + 1):
                with self.subTest(size=size, prefix=prefix):
                    request = consistency_request(prefix, items)
                    result = evaluate(request)
                    self.assertEqual(result["status"], "PASS")
                    self.assertEqual(result["calculated_old_root"], tree(items[:prefix]).hex())
                    self.assertEqual(result["calculated_new_root"], tree(items).hex())
                    self.assertEqual(len(request["proof"]), proof.consistency_length(prefix, size))
                    count += 1
        self.assertEqual(count, 2080)

    def test_fixed_upstream_reference_vectors(self):
        records = json.loads((Path(__file__).parent / "upstream_vectors.json").read_text())
        self.assertEqual(len(records["vectors"]), 196)
        differences = []
        for vector in records["vectors"]:
            with self.subTest(path=vector["source_path"]):
                result = evaluate(vector["request"])
                if vector.get("strict_width_override"):
                    self.assertEqual(result["status"], "OPEN")
                    self.assertEqual(result["errors"], ["invalid_sha256_hash"])
                    differences.append(vector["source_path"])
                elif vector["upstream_want_error"]:
                    self.assertIn(result["status"], {"FAIL", "OPEN"})
                else:
                    self.assertEqual(result["status"], "PASS")
        self.assertEqual(differences, ["testdata/consistency/additional/sizes-are-equal-one-and-proof-is-empty.json"])

    def test_well_formed_mutations_fail(self):
        items = tuple(f"leaf-{i}".encode() for i in range(7))
        inclusion = inclusion_request(2, items)
        consistency = consistency_request(3, items)
        mutated = []
        for request in [inclusion, consistency]:
            root_fields = ["root_hash"] if request["operation"] == "inclusion" else ["old_root", "new_root"]
            for field in root_fields:
                changed = copy.deepcopy(request)
                changed[field] = "00" * 32
                mutated.append(changed)
            for index in range(len(request["proof"])):
                changed = copy.deepcopy(request)
                changed["proof"][index] = "ff" * 32
                mutated.append(changed)
            changed = copy.deepcopy(request)
            changed["proof"] = list(reversed(changed["proof"]))
            mutated.append(changed)
        changed = copy.deepcopy(inclusion)
        changed["leaf"]["data"] = b"different leaf".hex()
        mutated.append(changed)
        for request in mutated:
            with self.subTest(request=request):
                result = evaluate(request)
                self.assertEqual(result["status"], "FAIL")
                self.assertTrue(result["complete"])
                self.assertEqual(result["errors"], ["root_mismatch"])

    def test_domain_and_child_order_are_binding(self):
        items = (b"a", b"b")
        request = inclusion_request(0, items)
        for wrong_root in [hashlib.sha256(tree(items[:1]) + tree(items[1:])).hexdigest(),
                           hashlib.sha256(b"\x01" + tree(items[1:]) + tree(items[:1])).hexdigest()]:
            changed = copy.deepcopy(request)
            changed["root_hash"] = wrong_root
            self.assertEqual(evaluate(changed)["status"], "FAIL")
        changed = copy.deepcopy(request)
        del changed["leaf"]
        changed["leaf_hash"] = hashlib.sha256(items[0]).hexdigest()
        self.assertEqual(evaluate(changed)["status"], "FAIL")

    def test_exact_proof_lengths_open(self):
        items = tuple(str(i).encode() for i in range(7))
        for request in [inclusion_request(6, items), consistency_request(3, items)]:
            for changed_proof in [request["proof"][:-1], request["proof"] + ["00" * 32]]:
                changed = copy.deepcopy(request)
                changed["proof"] = changed_proof
                self.assertEqual(evaluate(changed)["status"], "OPEN")
                self.assertEqual(evaluate(changed)["errors"], ["wrong_proof_length"])

    def test_empty_tree_and_same_size_contract(self):
        request = inclusion_request(0, (b"",))
        request["tree_size"] = 0
        self.assertEqual(evaluate(request)["status"], "OPEN")
        equal = consistency_request(1, (b"",))
        self.assertEqual(evaluate(equal)["status"], "PASS")
        different = copy.deepcopy(equal)
        different["new_root"] = "00" * 32
        self.assertEqual(evaluate(different)["status"], "FAIL")
        equal["proof"] = ["00" * 32]
        self.assertEqual(evaluate(equal)["errors"], ["wrong_proof_length"])
        for new_size in [0, 1, 7]:
            request = {"schema_version": 1, "hash_algorithm": "sha256", "operation": "consistency",
                       "old_size": 0, "new_size": new_size, "old_root": proof.empty_root().hex(),
                       "new_root": proof.empty_root().hex(), "proof": []}
            self.assertEqual(evaluate(request)["errors"], ["empty_old_tree_not_supported"])

    def test_uint64_extremes_and_65_node_consistency(self):
        maximum = (1 << 64) - 1
        self.assertEqual(len(proof.inclusion_directions(0, maximum)), 64)
        self.assertEqual(len(proof.inclusion_directions(maximum - 1, maximum)), 63)
        old = (1 << 63) - 1
        self.assertEqual(proof.consistency_length(old, maximum), 65)
        # Fake but structurally valid paths at the maximum size remain bounded.
        nodes = tuple(hashlib.sha256(f"n{i}".encode()).digest() for i in range(65))
        dummy = b"\0" * 32
        calculated_old, calculated_new = proof.consistency_roots(old, maximum, dummy, nodes)
        request = {"schema_version": 1, "hash_algorithm": "sha256", "operation": "consistency",
                   "old_size": old, "new_size": maximum,
                   "old_root": calculated_old.hex(), "new_root": calculated_new.hex(),
                   "proof": [n.hex() for n in nodes]}
        self.assertEqual(evaluate(request)["status"], "PASS")
        self.assertEqual(evaluate(request, Limits(proof_nodes=64))["errors"], ["proof_node_budget_exceeded"])
        request["new_size"] = 1 << 64
        self.assertEqual(evaluate(request)["errors"], ["invalid_new_size"])

    def test_leaf_preimage_and_encoding_contract(self):
        request = inclusion_request(0, (b"\x00\xffbinary\r\n",))
        encoded = copy.deepcopy(request)
        encoded["leaf"] = {"encoding": "base64", "data": base64.b64encode(b"\x00\xffbinary\r\n").decode()}
        self.assertEqual(evaluate(encoded)["status"], "PASS")
        hashed = copy.deepcopy(request)
        hashed["leaf_hash"] = tree((b"\x00\xffbinary\r\n",)).hex()
        del hashed["leaf"]
        self.assertEqual(evaluate(hashed)["leaf_preimage"], "OPEN")
        self.assertEqual(evaluate(hashed)["status"], "PASS")
        for bad in [{"encoding": "hex", "data": "0"}, {"encoding": "hex", "data": "00 00"},
                    {"encoding": "base64", "data": "/x=="}, {"encoding": "base64", "data": "AA\n=="},
                    {"encoding": "base64", "data": "é"}, {"encoding": "utf8", "data": "foo"},
                    {"encoding": "hex", "data": 123}, {"encoding": "hex", "data": "", "extra": 0}]:
            changed = copy.deepcopy(request)
            changed["leaf"] = bad
            self.assertEqual(evaluate(changed)["status"], "OPEN")
        encoded["leaf"] = {"encoding": "hex", "data": ""}
        self.assertEqual(evaluate(encoded, Limits(leaf_bytes=0))["status"], "FAIL")

    def test_input_is_immutable_and_output_omits_content(self):
        secret = b"PRIVATE_TEST_LEAF_DO_NOT_ECHO"
        request = inclusion_request(0, (secret,))
        raw = json.dumps(request).encode()
        preserved = raw[:]
        result = check_bytes(raw)
        self.assertEqual(raw, preserved)
        text = json.dumps(result)
        self.assertNotIn(secret.decode(), text)
        self.assertNotIn(secret.hex(), text)
        self.assertNotIn(base64.b64encode(secret).decode(), text)
        self.assertEqual(result["input_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["cvp_eligibility"], "OPEN")


if __name__ == "__main__":
    unittest.main()
