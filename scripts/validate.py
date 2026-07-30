#!/usr/bin/env python3
"""Validate a generated CSAF document against the CSAF 2.0 JSON schema.

Usage:
    python3 scripts/validate.py [document.json] [schema.json]

Defaults: out.json and schemas/csaf_json_schema.json (relative to the repo root).

Exit code is the number of schema errors (0 on success, capped at 125).
Requires: pip install jsonschema
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.stderr.write("Missing dependency: pip install jsonschema\n")
    sys.exit(127)


def main(argv: list[str]) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    doc_path = Path(argv[1]) if len(argv) > 1 else repo_root / "out.json"
    schema_path = Path(argv[2]) if len(argv) > 2 else repo_root / "schemas" / "csaf_json_schema.json"

    with schema_path.open() as f:
        schema = json.load(f)
    with doc_path.open() as f:
        document = json.load(f)

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))

    print(f"Document: {doc_path}")
    print(f"Schema:   {schema_path}")
    print()

    if not errors:
        print("OK — document is valid.")
        return 0

    for i, err in enumerate(errors, 1):
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        message = err.message if len(err.message) < 200 else err.message[:197] + "..."
        print(f"{i}. [{path}] {message}")
    print()
    print(f"Total errors: {len(errors)}")
    return min(len(errors), 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
