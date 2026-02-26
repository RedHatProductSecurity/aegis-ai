#!/usr/bin/env python3
"""
Call the Aegis REST API with Kerberos delegation enabled.

Delegation allows the Aegis server to call OSIDB on your behalf (pass-through auth).
Requires: kinit -f (forwardable ticket), requests-gssapi.

Usage:
    python scripts/aegis-api-with-delegation.py GET /api/v1/status
    python scripts/aegis-api-with-delegation.py POST /api/v1/analysis/cve/suggest-impact '{"cve_id":"CVE-2026-27521"}'

Environment:
    AEGIS_API_URL: Base URL (default: http://aegis-stage.example.com:9000)
"""

import argparse
import json
import os
import sys

import requests
from requests_gssapi import HTTPSPNEGOAuth


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Call Aegis REST API with Kerberos delegation"
    )
    parser.add_argument("method", choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    parser.add_argument(
        "path", help="API path (e.g. /api/v1/analysis/cve/suggest-impact)"
    )
    parser.add_argument(
        "body",
        nargs="?",
        default=None,
        help='JSON body for POST/PUT/PATCH (e.g. \'{"cve_id":"CVE-2026-27521"}\')',
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print response headers",
    )
    args = parser.parse_args()

    base_url = os.environ.get("AEGIS_API_URL", "http://aegis-stage.example.com:9000")
    url = f"{base_url.rstrip('/')}{args.path}"

    auth = HTTPSPNEGOAuth(delegate=True)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    body_json: object | None = None
    if args.body:
        try:
            body_json = json.loads(args.body)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON body: {e}", file=sys.stderr)
            return 1

    try:
        resp = requests.request(
            args.method,
            url,
            auth=auth,
            headers=headers,
            json=body_json,
        )
    except requests.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return 1

    print(f"Status: {resp.status_code} {resp.reason}")
    if args.verbose:
        print(f"Headers: {dict(resp.headers)}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except (ValueError, json.JSONDecodeError):
        print(resp.text)

    return 0 if resp.ok else 1


if __name__ == "__main__":
    sys.exit(main())
