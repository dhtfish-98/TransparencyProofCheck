"""CLI: JSON to stdout; 0=PASS, 1=FAIL, 2=OPEN/usage error."""

import argparse
import json

from .evidence import Limits, open_report
from .input import check_file


class _InvalidArguments(ValueError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's default error prints the caller's argument text to stderr.
        raise _InvalidArguments("invalid_arguments")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="Offline SHA-256 Merkle proof relation check; roots require external trust.")
    parser.add_argument("input", help="One local regular JSON file; symlinks and '..' path segments are rejected")
    parser.add_argument("--max-input-bytes", type=int, default=524_288)
    parser.add_argument("--max-leaf-bytes", type=int, default=65_536)
    parser.add_argument("--max-proof-nodes", type=int, default=65)
    parser.add_argument("--max-json-depth", type=int, default=16)
    try:
        args = parser.parse_args(argv)
        limits = Limits(args.max_input_bytes, args.max_leaf_bytes, args.max_proof_nodes, args.max_json_depth)
        report = check_file(args.input, limits)
    except _InvalidArguments:
        report = open_report("invalid_arguments")
    except ValueError:
        report = open_report("invalid_limits")
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]
