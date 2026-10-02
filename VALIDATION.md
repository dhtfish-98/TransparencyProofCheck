# Measured validation

Local validation on 2026-10-02 used CPython 3.14.6 on macOS arm64. All **22
unittest methods passed** from source and against separately installed wheel
and source-distribution packages. The final packages are rebuilt after this
record is included, then installed and tested again; their exact SHA-256 values
and source inventory are recorded in the accompanying engineering JSON.

The independent raw-leaf recursive oracle (it imports no production proof/hash
functions) checks all **2,080 inclusion paths** and **2,080 positive-prefix
consistency cases**, including equal sizes, for tree sizes 1 through 64. This
covers first/last leaves, single leaves, powers of two and non-perfect trees.
The tree oracle does not pad or duplicate leaves. Fixed empty-root/leaf hashes,
leaf/node domain separation, child order, changed roots/leaves/proof nodes and
short/long paths are also checked.

The **196 fixed upstream reference vectors** comprise 98 inclusion and 98
consistency probes, each retaining its source path, SHA-256 and Git blob ID.
There are 6 positive and 92 negative probes in each directory. All supported
positive cases pass and all negative cases return FAIL or OPEN. One upstream
positive consistency probe has equal 12-byte roots at size 1; it returns OPEN
under the stricter 32-byte SHA-256 contract. This is an intentional acceptance
difference, not a claim of complete upstream-equivalent results. The original
Go verifier/generator was not executed.

A separate read-only agent compared an independently expressed RFC-style
verification loop to those fixed probes (98/98 inclusion; 97/98 consistency,
with the same known width difference). It also compared exact proof-length
formulas with recursive shape generation for 65,536 combinations up to size
256. This independently checks mathematics and fixtures; it does not represent
a complete upstream or package audit.

Boundary checks cover uint64 sizes, an exactly 65-node consistency shape near
the maximum size, proof/leaf/input/depth budgets, invalid widths and encodings,
boolean/float/negative/overflow sizes, duplicate keys and unsupported schema,
hash/compact/subtree operations. The extreme-size case uses synthetic proof
hashes to exercise the bounded structure, not a materialized enormous tree.
All zero-old-size consistency requests and empty-tree inclusion return OPEN.

The local reader tests cover final/parent symlinks, raw `..` segments, missing
files, directories, FIFOs without blocking, unsupported safe-read primitives,
observed metadata changes and input preservation. CLI tests check the actual
0/1/2 outcomes, validated budgets, no source-path/raw-leaf echo and unchanged
input bytes. There are also three direct installed-command cases in each
consumer environment, producing PASS/0, FAIL/1 and OPEN/2.

CLI argument regressions cover empty arguments, unknown options and nonnumeric
limits: each returns JSON OPEN/2 with fixed `invalid_arguments`, no argument
echo and empty stderr. `--help` remains ordinary help with exit 0. The original
argparse error behavior could echo supplied arguments to stderr; this was
replaced before publication. Final installed consumers repeat these checks.

The source distribution includes tests, converted fixture data, examples,
workflow, source-review record and attribution documents. The wheel carries all
six runtime modules, original LICENSE/NOTICE, and provenance/scope/validation
documents plus examples under `share/transparency-proof-check`. Package
metadata declares **no third-party runtime dependencies**. The isolated local
build used `build 1.6.1` with `setuptools 84.0.0`; these are build tools only.

Every new runtime module, test/oracle, package configuration, workflow and
attribution/scope document was reviewed. The workflow uses commit-pinned
actions and read-only repository permissions. Its YAML and embedded
Python/shell syntax were checked. Python 3.11 is configured in remote CI but was
not locally executed. **Remote CI and GitHub publication remain OPEN.**

Mathematical tests and package installation do not establish root authenticity,
log/operator identity, leaf/content authenticity, checkpoint signature
validity, CVP eligibility or model access; those remain **OPEN**. This delivery
implements the stated SHA-256 proof contract and does not claim the entire
upstream library or its compact/subtree/multi-hash extensions.
