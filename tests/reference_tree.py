"""Independent recursive test oracle, using raw synthetic leaf bytes only.

It imports no production proof/hash functions. It builds the complete test
tree, unlike the runtime verifier's bounded path-only iteration.
"""

import hashlib


def tree(items: tuple[bytes, ...]) -> bytes:
    if not items:
        return hashlib.sha256(b"").digest()
    if len(items) == 1:
        return hashlib.sha256(b"\x00" + items[0]).digest()
    pivot = 1
    while pivot * 2 < len(items):
        pivot *= 2
    return hashlib.sha256(b"\x01" + tree(items[:pivot]) + tree(items[pivot:])).digest()


def inclusion(index: int, items: tuple[bytes, ...]) -> list[bytes]:
    if len(items) == 1:
        return []
    pivot = 1
    while pivot * 2 < len(items):
        pivot *= 2
    if index < pivot:
        return inclusion(index, items[:pivot]) + [tree(items[pivot:])]
    return inclusion(index - pivot, items[pivot:]) + [tree(items[:pivot])]


def consistency(prefix: int, items: tuple[bytes, ...], known: bool = True) -> list[bytes]:
    if prefix == len(items):
        return [] if known else [tree(items)]
    pivot = 1
    while pivot * 2 < len(items):
        pivot *= 2
    if prefix <= pivot:
        return consistency(prefix, items[:pivot], known) + [tree(items[pivot:])]
    return consistency(prefix - pivot, items[pivot:], False) + [tree(items[:pivot])]


def inclusion_request(index: int, items: tuple[bytes, ...]) -> dict:
    return {"schema_version": 1, "hash_algorithm": "sha256", "operation": "inclusion",
            "tree_size": len(items), "leaf_index": index, "root_hash": tree(items).hex(),
            "leaf": {"encoding": "hex", "data": items[index].hex()},
            "proof": [node.hex() for node in inclusion(index, items)]}


def consistency_request(prefix: int, items: tuple[bytes, ...]) -> dict:
    return {"schema_version": 1, "hash_algorithm": "sha256", "operation": "consistency",
            "old_size": prefix, "new_size": len(items), "old_root": tree(items[:prefix]).hex(),
            "new_root": tree(items).hex(), "proof": [node.hex() for node in consistency(prefix, items)]}
