# Origin and attribution

The source used for semantic review and fixed test references is
`transparency-dev/merkle` at the immutable commit
`fbbcd741c3d1c69d8498487baa8edc9e5824847c`.

Repository: https://github.com/transparency-dev/merkle

License: Apache License 2.0. The unchanged upstream license text is included in
`LICENSE`; SHA-256:
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
Google LLC copyright notices from the reviewed original files remain in
`NOTICE`. The original repository remains the property/work of its authors.

The semantic review read the selected hash interface, RFC6962 hashing source,
proof verification/source shape code, corresponding hash/proof tests, and
license. The 98 inclusion and 98 consistency JSON vectors were converted from
base64 hashes to hexadecimal, and null proof arrays to empty arrays; each
vector records the original path and SHA-256. The source review manifest
identifies the exact files and their Git blob IDs. No upstream executable or
network log was run or contacted for validation. This selected-core review is
not a whole-repository semantic audit.

All Python runtime, local JSON/file boundary, CLI, independent synthetic tree
oracle, test assertions, package configuration and documentation in this
project were written as a new implementation with Codex assistance. The
runtime does not import, execute, bind to, or shell out to the Go library.
The fixed vector data retains Apache-2.0 attribution. Standard mathematical
definitions were implemented in new Python code; RFC prose and pseudocode
were not copied verbatim.

The applicant must accurately describe their own review, implementation and
testing contribution. This package records assisted development and does not
declare exclusive human authorship. No project name, repository count, test
pass or publication establishes CVP eligibility, organizational status,
identity verification or exemption from cyber safeguards; those remain OPEN.
