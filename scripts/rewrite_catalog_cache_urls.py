#!/usr/bin/env python3
"""Rewrite catalog_cache fixture ``url`` fields to role-token placeholders.

Uses ``normalize_cache_url`` so committed fixtures store ``{bomq_primary}``,
``{bomq_community}``, and ``{anitya}`` instead of deployment-specific hosts.

Set ``AEGIS_BOMQ_URL`` / ``AEGIS_BOMQ_COMMUNITY_URL`` / ``AEGIS_ANITYA_URL`` to
the concrete hosts currently stored in the fixtures before running, e.g.:

    AEGIS_BOMQ_URL=https://bomq.example \\
    AEGIS_BOMQ_COMMUNITY_URL=https://bomq-community.example \\
    AEGIS_ANITYA_URL=https://release-monitoring.org \\
      uv run python scripts/rewrite_catalog_cache_urls.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from evals.utils.catalog_cache import (
    CACHE_DIR,
    normalize_cache_url,
)


def _scheme_netloc(url: str) -> str | None:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def main() -> None:
    cache_dir = Path(CACHE_DIR)
    if not cache_dir.is_dir():
        print(f"error: cache dir not found: {cache_dir}", file=sys.stderr)
        sys.exit(1)

    rewritten = 0
    unchanged = 0
    for path in sorted(cache_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "url" not in data:
            print(f"  skip {path.name}: missing url field", file=sys.stderr)
            continue
        original = data["url"]
        if not isinstance(original, str):
            print(f"  skip {path.name}: url is not a string", file=sys.stderr)
            continue
        normalized = normalize_cache_url(original)
        if normalized == original:
            unchanged += 1
            continue
        data["url"] = normalized
        path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
        rewritten += 1

    misses = cache_dir / "MISSES.txt"
    misses_rewritten = 0
    if misses.is_file():
        lines = misses.read_text(encoding="utf-8").splitlines()
        new_lines = [
            normalize_cache_url(line) if line.strip() else line for line in lines
        ]
        if new_lines != lines:
            misses.write_text(
                "\n".join(new_lines) + ("\n" if lines else ""), encoding="utf-8"
            )
            misses_rewritten = sum(
                1 for a, b in zip(lines, new_lines, strict=True) if a != b
            )

    print(
        f"done: {rewritten} json rewritten, {unchanged} unchanged"
        + (f", {misses_rewritten} MISSES.txt lines" if misses.is_file() else ""),
        file=sys.stderr,
    )

    # Warn if any absolute http(s) hosts remain (likely env not set to match fixtures).
    remaining_hosts: set[str] = set()
    for path in cache_dir.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        url = data.get("url") if isinstance(data, dict) else None
        if isinstance(url, str):
            host = _scheme_netloc(url)
            if host:
                remaining_hosts.add(host)
    if remaining_hosts:
        print(
            "warning: absolute hosts still present; set AEGIS_BOMQ_* / "
            f"AEGIS_ANITYA_URL to match: {', '.join(sorted(remaining_hosts))}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
