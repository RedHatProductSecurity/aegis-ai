#!/usr/bin/env python3
"""Import eval cache fixtures from a CI log containing [cache-dump] lines.

Usage:
    python scripts/import_evals_cache.py <logfile>
    cat logfile | python scripts/import_evals_cache.py -

Parses [cache-dump] markers emitted by evals/conftest.py at session end,
decodes the base64 payloads, and writes each fixture to the correct cache
directory.
"""

import base64
import binascii
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CACHE_DIRS = {
    "catalog": Path("evals/catalog_cache"),
    "external_references": Path("evals/external_references_cache"),
    "ghsa": Path("evals/ghsa_cache"),
    "osidb": Path("evals/osidb_cache"),
}

DUMP_RE = re.compile(r"\[cache-dump\] type=(\S+) file=(\S+) base64=(\S+)")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <logfile>", file=sys.stderr)
        print(f"       cat logfile | {sys.argv[0]} -", file=sys.stderr)
        sys.exit(1)

    source = sys.argv[1]
    if source == "-":
        lines = sys.stdin.readlines()
    else:
        with open(source) as f:
            lines = f.readlines()

    force = "--force" in sys.argv

    imported = 0
    skipped = 0
    errors = 0

    for line in lines:
        m = DUMP_RE.search(line)
        if not m:
            continue

        cache_type, filename, b64_data = m.group(1), m.group(2), m.group(3)

        cache_dir = CACHE_DIRS.get(cache_type)
        if not cache_dir:
            print(f"  unknown cache type: {cache_type}", file=sys.stderr)
            errors += 1
            continue

        safe_name = Path(filename).name
        if safe_name != filename or not safe_name:
            print(f"  rejected unsafe filename: {filename}", file=sys.stderr)
            errors += 1
            continue

        if cache_dir.is_symlink():
            print(f"  rejected symlinked cache dir: {cache_dir}", file=sys.stderr)
            errors += 1
            continue

        raw_target = cache_dir / safe_name
        if raw_target.is_symlink():
            print(f"  rejected symlink: {raw_target}", file=sys.stderr)
            errors += 1
            continue

        target = raw_target.resolve()
        if not target.is_relative_to(REPO_ROOT):
            print(f"  rejected path outside repo: {filename}", file=sys.stderr)
            errors += 1
            continue

        if target.exists() and not force:
            print(f"  skip (exists): {target}", file=sys.stderr)
            skipped += 1
            continue

        try:
            data = base64.b64decode(b64_data, validate=True)
        except binascii.Error as e:
            print(f"  decode error for {filename}: {e}", file=sys.stderr)
            errors += 1
            continue

        try:
            json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"  invalid JSON in {filename}: {e}", file=sys.stderr)
            errors += 1
            continue

        cache_dir.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        print(f"  imported: {target}")
        imported += 1

    print(
        f"\nDone: {imported} imported, {skipped} skipped, {errors} errors",
        file=sys.stderr,
    )
    if imported == 0 and skipped == 0 and errors == 0:
        print("No [cache-dump] lines found in input.", file=sys.stderr)
        sys.exit(1)
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
