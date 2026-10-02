"""Strict, content-private JSON evidence contract for local proof checking."""

import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
import json
import re

from . import proof


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 524_288
    leaf_bytes: int = 65_536
    proof_nodes: int = 65
    json_depth: int = 16

    def __post_init__(self) -> None:
        ceilings = {"input_bytes": 8_388_608, "leaf_bytes": 1_048_576,
                    "proof_nodes": 65, "json_depth": 64}
        for name, maximum in ceilings.items():
            value = getattr(self, name)
            minimum = 0 if name in {"leaf_bytes", "proof_nodes"} else 1
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"invalid_limit_{name}")


class InvalidEvidence(ValueError):
    """A stable error code. It contains no untrusted values or source text."""


def _limits(value: Limits | None) -> Limits:
    if value is None:
        return Limits()
    if not isinstance(value, Limits):
        raise TypeError("limits must be Limits or None")
    return value


def open_report(code: str, *, raw: bytes | None = None, limits: Limits | None = None) -> dict:
    result = {
        "schema_version": 1, "status": "OPEN", "complete": False,
        "mathematical_relation": "NOT_EVALUATED", "errors": [code],
        "root_authenticity": "OPEN", "content_authenticity": "OPEN",
        "cvp_eligibility": "OPEN",
        "trust_requirement": "Caller must independently trust the supplied roots and tree sizes.",
    }
    if raw is not None:
        result.update(input_bytes=len(raw), input_sha256=hashlib.sha256(raw).hexdigest())
    if limits is not None:
        result["limits"] = asdict(limits)
    return result


def _depth_check(raw: bytes, maximum: int) -> None:
    depth = 0
    in_string = escaped = False
    for value in raw:
        if in_string:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                in_string = False
        elif value == 34:
            in_string = True
        elif value in (91, 123):
            depth += 1
            if depth > maximum:
                raise InvalidEvidence("json_depth_exceeded")
        elif value in (93, 125):
            depth -= 1
    # Syntax validation is delegated to json.loads; this pass bounds its stack.


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEvidence("duplicate_json_key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise InvalidEvidence("non_finite_json_number")


def _keys(value: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    if set(value) - required - optional:
        raise InvalidEvidence("unknown_field")
    if required - set(value):
        raise InvalidEvidence("missing_field")


def _integer(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= proof.MAX_TREE_SIZE:
        raise InvalidEvidence(code)
    return value


def _hash(value: object) -> bytes:
    if type(value) is not str or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise InvalidEvidence("invalid_sha256_hash")
    return bytes.fromhex(value)


def _nodes(value: object, maximum: int) -> tuple[bytes, ...]:
    if type(value) is not list:
        raise InvalidEvidence("invalid_proof_array")
    if len(value) > maximum:
        raise InvalidEvidence("proof_node_budget_exceeded")
    return tuple(_hash(node) for node in value)


def _leaf(value: object, maximum: int) -> bytes:
    if type(value) is not dict:
        raise InvalidEvidence("invalid_leaf_object")
    _keys(value, {"encoding", "data"})
    data = value["data"]
    if type(data) is not str:
        raise InvalidEvidence("invalid_leaf_data")
    if value["encoding"] == "hex":
        if len(data) > maximum * 2:
            raise InvalidEvidence("leaf_byte_budget_exceeded")
        if len(data) % 2 or re.fullmatch(r"[0-9a-fA-F]*", data) is None:
            raise InvalidEvidence("invalid_leaf_hex")
        decoded = bytes.fromhex(data)
    elif value["encoding"] == "base64":
        if len(data) > ((maximum + 2) // 3) * 4:
            raise InvalidEvidence("leaf_byte_budget_exceeded")
        try:
            decoded = base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error):
            raise InvalidEvidence("invalid_leaf_base64") from None
        if base64.b64encode(decoded).decode("ascii") != data:
            raise InvalidEvidence("non_canonical_leaf_base64")
    else:
        raise InvalidEvidence("unsupported_leaf_encoding")
    if len(decoded) > maximum:
        raise InvalidEvidence("leaf_byte_budget_exceeded")
    return decoded


def _evaluate(document: object, limits: Limits) -> dict:
    if type(document) is not dict:
        raise InvalidEvidence("invalid_document_object")
    common = {"schema_version", "hash_algorithm", "operation", "proof"}
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise InvalidEvidence("unsupported_schema_version")
    if document.get("hash_algorithm") != "sha256":
        raise InvalidEvidence("unsupported_hash_algorithm")
    operation = document.get("operation")
    if operation == "inclusion":
        _keys(document, common | {"tree_size", "leaf_index", "root_hash"}, {"leaf", "leaf_hash"})
        if ("leaf" in document) == ("leaf_hash" in document):
            raise InvalidEvidence("exactly_one_leaf_form_required")
        size = _integer(document["tree_size"], "invalid_tree_size")
        index = _integer(document["leaf_index"], "invalid_leaf_index")
        if not size or index >= size:
            raise InvalidEvidence("leaf_index_outside_tree")
        root = _hash(document["root_hash"])
        nodes = _nodes(document["proof"], limits.proof_nodes)
        directions = proof.inclusion_directions(index, size)
        if len(nodes) != len(directions):
            raise InvalidEvidence("wrong_proof_length")
        raw_leaf = "leaf" in document
        leaf = proof.leaf_digest(_leaf(document["leaf"], limits.leaf_bytes)) if raw_leaf else _hash(document["leaf_hash"])
        calculated = proof.inclusion_root(leaf, nodes, directions)
        matched = calculated == root
        return {"operation": operation, "status": "PASS" if matched else "FAIL",
                "complete": True, "mathematical_relation": "MATCH" if matched else "MISMATCH",
                "errors": [] if matched else ["root_mismatch"],
                "tree_size": size, "leaf_index": index, "proof_nodes": len(nodes),
                "calculated_root": calculated.hex(),
                "leaf_preimage": "HASHED_CALLER_BYTES" if raw_leaf else "OPEN"}
    if operation == "consistency":
        _keys(document, common | {"old_size", "new_size", "old_root", "new_root"})
        old_size = _integer(document["old_size"], "invalid_old_size")
        new_size = _integer(document["new_size"], "invalid_new_size")
        if old_size > new_size:
            raise InvalidEvidence("tree_size_decreased")
        old_root, new_root = _hash(document["old_root"]), _hash(document["new_root"])
        nodes = _nodes(document["proof"], limits.proof_nodes)
        if old_size == 0:
            raise InvalidEvidence("empty_old_tree_not_supported")
        if len(nodes) != proof.consistency_length(old_size, new_size):
            raise InvalidEvidence("wrong_proof_length")
        calculated_old, calculated_new = proof.consistency_roots(old_size, new_size, old_root, nodes)
        matched = calculated_old == old_root and calculated_new == new_root
        return {"operation": operation, "status": "PASS" if matched else "FAIL",
                "complete": True, "mathematical_relation": "MATCH" if matched else "MISMATCH",
                "errors": [] if matched else ["root_mismatch"],
                "old_size": old_size, "new_size": new_size, "proof_nodes": len(nodes),
                "calculated_old_root": calculated_old.hex(), "calculated_new_root": calculated_new.hex()}
    raise InvalidEvidence("unsupported_operation")


def check_bytes(raw: bytes, limits: Limits | None = None) -> dict:
    """Check immutable JSON bytes. PASS only concerns caller-supplied hashes.

    Invalid/unsupported/budgeted evidence returns OPEN. A well-formed proof
    that reconstructs different roots returns FAIL. No raw values are echoed.
    """
    limits = _limits(limits)
    if type(raw) is not bytes:
        raise TypeError("raw must be bytes")
    if len(raw) > limits.input_bytes:
        return open_report("input_byte_budget_exceeded", limits=limits)
    report = open_report("not_evaluated", raw=raw, limits=limits)
    try:
        _depth_check(raw, limits.json_depth)
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        result = _evaluate(document, limits)
    except InvalidEvidence as error:
        report["errors"] = [str(error)]
        return report
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        report["errors"] = ["invalid_json_or_internal_shape"]
        return report
    report.update(result)
    return report
