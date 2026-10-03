# Defensive scope

Use this project to inspect proof evidence you are authorized to review. Its
only supported decisions are offline SHA-256 Merkle inclusion and positive
old-prefix consistency relations, relative to explicit caller-provided roots
and tree sizes. A matching proof helps detect a mismatched inclusion path or
inconsistent append-only checkpoint relation.

The caller must obtain trusted checkpoints independently. Roots, sizes, leaf
bytes and proofs in one untrusted JSON file can all be fabricated coherently.
Therefore mathematical PASS does not authenticate the root, the log operator,
the leaf content, a certificate, or a time/identity claim. Those conclusions
remain OPEN. Equal-size consistency only compares equal positive-size roots
with an empty proof.

The runtime reads one bounded local regular JSON file or immutable bytes. It
does not connect to a network, fetch logs, scan directories, evaluate leaf
contents, mutate input, sign roots, upload evidence or generate production
proofs. Proof generation appears only in synthetic tests. Unknown operations
(including compact range and subtree APIs), other hashes, invalid inputs and
exhausted budgets return OPEN.

The original shortlist included a compact-range core. This delivery was
explicitly narrowed to complete inclusion/consistency verification, with a
separate safe input and reporting boundary. Unsupported compact/subtree APIs
are not counted as implemented. Multi-hash support and full CT protocol
integration are outside this project.

Reports omit raw leaf content and source paths; they retain calculated hashes
and the digest of a successfully bounded input for evidence matching. Stable
files are required for reproducible review. Descriptor change checks cannot
establish a filesystem snapshot or protect against every modification race.

Defensive topic fit is conditional on this authorized scope. CVP eligibility,
applicant identity, organizational details, real safeguard impact and any
model-access approval remain OPEN and are separate from engineering results.
