> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# TransparencyProofCheck

TransparencyProofCheck verifies **offline SHA-256 Merkle inclusion and tree
consistency relations** against roots and sizes supplied by the caller. It is a
new Python implementation of this bounded contract, with no runtime dependency
on the original Go library. It can help review proof evidence before relying on
an artifact or append-only log claim.

**PASS means the mathematical relation matches these inputs.** The caller must
independently establish that the roots and tree sizes came from a trusted
checkpoint. Root signatures, log identity, content authenticity, timestamp
validity and CVP eligibility remain **OPEN**, including after a proof passes.

## Install and run

Python 3.11 or newer is required. The safe file reader supports POSIX systems
with `O_NOFOLLOW` and descriptor-relative directory access. Unsupported readers
return OPEN. There are no third-party runtime dependencies.

```sh
python3 -m pip install .
transparency-proof-check examples/inclusion-empty-leaf.json
transparency-proof-check examples/consistency-same-size.json
```

The command reads one local regular JSON file, prints one JSON report to stdout,
and exits **0 for PASS**, **1 for FAIL**, **2 for OPEN**. Missing/unknown arguments
or a nonnumeric limit produce a fixed `invalid_arguments` JSON OPEN report,
without echoing arguments to stdout or stderr. `--help` displays ordinary help
and exits 0.
It accepts no network URL, stdin stream, directory scan, output file or signature
operation. The input is never written. Symlinks in any path component and raw
`..` segments are rejected. Use a physical path when a system directory is a
symlink; the command does not silently resolve it.

## Input format

All keys are case-sensitive. Unknown fields, duplicate JSON keys, unsupported
algorithms/operations, non-UTF-8 input, non-finite numbers, floats or boolean
sizes, and malformed evidence return OPEN. Schema version is the integer `1`.
Hashes are exactly 64 hexadecimal characters (32 bytes). Uppercase hexadecimal
is accepted; whitespace is not. Proof nodes are ordered from the leaf/subtree
towards the root. They must have the **exact** count for the supplied tree shape.

An inclusion request contains exactly one of `leaf` or `leaf_hash`:

```json
{
  "schema_version": 1,
  "hash_algorithm": "sha256",
  "operation": "inclusion",
  "tree_size": 1,
  "leaf_index": 0,
  "root_hash": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "leaf": {"encoding": "hex", "data": ""},
  "proof": []
}
```

`leaf.data` is either strict even-length hexadecimal or canonical padded base64,
as selected by `leaf.encoding` (`hex` or `base64`). An empty string encodes empty
leaf bytes in either encoding. `leaf_hash`, when used instead, supplies the
already domain-separated 32-byte leaf hash; its relationship to any actual leaf
preimage remains OPEN. A leaf is the exact caller-provided byte sequence. The
tool does not construct or validate CT v1/v2 leaf wire structures or certificates.

A consistency request supplies both roots:

```json
{
  "schema_version": 1,
  "hash_algorithm": "sha256",
  "operation": "consistency",
  "old_size": 1,
  "new_size": 1,
  "old_root": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "new_root": "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "proof": []
}
```

Sizes and indices are non-boolean integers in `0..2**64-1`. Inclusion requires
`tree_size > 0` and `0 <= leaf_index < tree_size`. Consistency requires
`0 < old_size <= new_size`. At equal positive sizes the proof must be empty and
the two roots must match. A size decrease, inclusion in an empty tree, and every
`old_size=0` consistency request return OPEN. Empty old-tree consistency is an
explicit unsupported case, following the fixed upstream contract; this tool
does not return a vacuous PASS for it.

## Results and budgets

PASS and FAIL set `complete=true`: the supported mathematical relation was
evaluated. A well-formed, correctly sized proof that reconstructs a different
root yields FAIL. Invalid structure, unsupported evidence, or an exhausted
budget yields OPEN and `complete=false`.

Reports include fixed error codes, the actual validated limits when argument
validation succeeds, the input digest/byte count after a bounded
read, calculated root hashes for evaluated relations, and the external trust
requirement. They omit raw leaf bytes, encoded leaf values, JSON snippets,
paths, and caller-supplied free text. Derived hashes remain part of the report.

| Limit | Default | Maximum accepted configuration |
|---|---:|---:|
| Input JSON bytes | 524,288 | 8,388,608 |
| Decoded leaf bytes | 65,536 | 1,048,576 |
| Proof nodes | 65 | 65 |
| JSON nesting depth | 16 | 64 |

The options are `--max-input-bytes`, `--max-leaf-bytes`, `--max-proof-nodes`,
and `--max-json-depth`. Leaf/proof budgets may be zero. Input/depth budgets must
be positive. Tree sizes never cause the tool to build a tree: shape walks take
at most 64 iterations, and hashes consume at most 65 supplied proof nodes.
JSON bytes and nesting are bounded before parsing. The local reader refuses
non-regular files and checks descriptor metadata before and after reading;
detected changes yield OPEN. This is not a filesystem snapshot or protection
against an adversary able to race modifications while restoring all observed
metadata. Use stable evidence files for a review.

Python API:

```python
from transparency_proof_check import Limits, check_bytes, check_file

report = check_file("examples/inclusion-empty-leaf.json", Limits())
report_from_bytes = check_bytes(b'{"schema_version":77}')  # OPEN
```

## Scope and provenance

The hash construction is `SHA256(0x00 || leaf)` and
`SHA256(0x01 || left_hash || right_hash)`. Non-perfect trees split at the largest
strictly smaller power of two; no leaf is padded or duplicated. The mathematics
follows [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1)
and [RFC 9162 §2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1).
Supporting these hash/proof relations does not implement either full CT protocol.

The reviewed reference is
[transparency-dev/merkle at fbbcd741c3d1c69d8498487baa8edc9e5824847c](https://github.com/transparency-dev/merkle/tree/fbbcd741c3d1c69d8498487baa8edc9e5824847c).
The test suite carries 196 transformed fixed reference JSON vectors with their
original paths and SHA-256 values. One upstream positive vector uses equal
12-byte roots at size 1. This implementation returns OPEN for it because all
roots must be SHA-256 width; it does not claim identical acceptance for that
case. The upstream program and proof generator were not executed.

This delivery covers SHA-256 inclusion and positive-prefix consistency checking.
The earlier selection record also mentioned compact ranges; that API was
explicitly removed from this delivery's scope. Compact range construction or
merging, subtree extensions, other hash algorithms, online logs, proof
generation outside synthetic tests, and checkpoint signing are unsupported.
This is not a rewrite of the entire Go library.

[ORIGIN.md](<ORIGIN.md>), [NOTICE](<NOTICE>), and [SOURCE_REVIEW.json](<../SOURCE_REVIEW.json>)
retain original ownership, license and reviewed-source evidence.
New implementation author and maintainer: dhtfish98. This record
does not establish the applicant's personal authorship or CVP approval.
See [VALIDATION.md](<VALIDATION.md>) for measured checks and
[DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>) for the defensive boundary.

Local file I/O requires the positive integer OS protection flags documented by
the reader/writer. Missing, zero, None, Boolean or non-integer flags return a
controlled OPEN/error before requested filesystem input/output instead of
weakening the boundary. Native
Windows file I/O is not verified; the current verification is macOS POSIX.

Directory descriptor capability contract: `os.supports_dir_fd` must be a set or frozenset containing `os.open` before requested local file access. Missing, malformed or incomplete capability declarations return the existing controlled OPEN/error result. This finite POSIX contract is checked locally; native Windows file operations are not implemented or claimed.
