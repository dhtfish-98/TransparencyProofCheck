"""Bounded SHA-256 Merkle mathematics, independent of the Go upstream.

All callers in evidence.py validate uint64 sizes and 32-byte hashes first.
Proofs are sibling hashes ordered from the leaf/subtree towards the root.
"""

import hashlib

MAX_TREE_SIZE = (1 << 64) - 1
HASH_BYTES = 32


def empty_root() -> bytes:
    return hashlib.sha256(b"").digest()


def leaf_digest(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def inclusion_directions(index: int, size: int) -> tuple[bool, ...]:
    """Return root-to-leaf sibling positions; True means sibling on right.

    A non-perfect tree splits at its largest strictly smaller power of two.
    Walking the shape avoids padding/duplicating the last leaf. At most 64
    iterations are possible under the validated uint64 contract.
    """
    directions = []
    while size > 1:
        split = 1 << ((size - 1).bit_length() - 1)
        right_sibling = index < split
        directions.append(right_sibling)
        if right_sibling:
            size = split
        else:
            index -= split
            size -= split
    return tuple(directions)


def inclusion_root(leaf: bytes, nodes: tuple[bytes, ...], directions: tuple[bool, ...]) -> bytes:
    result = leaf
    for sibling, on_right in zip(nodes, reversed(directions), strict=True):
        result = _parent(result, sibling) if on_right else _parent(sibling, result)
    return result


def consistency_length(old_size: int, new_size: int) -> int:
    """Count the RFC subproof shape without allocating or recursive calls."""
    known_root = True
    count = 0
    while old_size != new_size:
        split = 1 << ((new_size - 1).bit_length() - 1)
        count += 1
        if old_size <= split:
            new_size = split
        else:
            old_size -= split
            new_size -= split
            known_root = False
    return count + (0 if known_root else 1)


def consistency_roots(old_size: int, new_size: int, old_root: bytes,
                      nodes: tuple[bytes, ...]) -> tuple[bytes, bytes]:
    """Reconstruct both roots; exact shape/length was checked by the caller.

    Trailing right edges of the old prefix establish the starting subtree.
    Nodes to its left extend both roots; nodes to its right extend only the
    new root. The old root is only a seed when the old tree is perfect.
    """
    if old_size == new_size:
        return old_root, old_root
    old_cursor, new_cursor = old_size - 1, new_size - 1
    while old_cursor & 1:
        old_cursor >>= 1
        new_cursor >>= 1
    if old_size & (old_size - 1) == 0:
        earlier = later = old_root
        offset = 0
    else:
        earlier = later = nodes[0]
        offset = 1
    for node in nodes[offset:]:
        if not new_cursor:
            raise ValueError("internal_proof_shape")
        if old_cursor & 1 or old_cursor == new_cursor:
            earlier = _parent(node, earlier)
            later = _parent(node, later)
            while old_cursor and not old_cursor & 1:
                old_cursor >>= 1
                new_cursor >>= 1
        else:
            later = _parent(later, node)
        old_cursor >>= 1
        new_cursor >>= 1
    # An internal shape discrepancy must never be presented as a root match.
    if old_cursor or new_cursor:
        raise ValueError("internal_proof_shape")
    return earlier, later
