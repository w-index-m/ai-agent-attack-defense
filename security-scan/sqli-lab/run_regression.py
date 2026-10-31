"""
Regression test for this lab's own detection scripts (auto_vuln_scanner.py /
session_vuln_check.py) -- NOT a security scan of this repository's own code.

See README.ja.md's "TODO: CIの集計(scripts/summarize.py)への組み込み" section
for why: vulnerable_app.py is an intentionally-vulnerable demo app, not this
repository's own code, so running the scanners against it in CI would just
re-detect the same known-intentional bugs every time -- not a useful CI gate
in the way Semgrep/Trivy/gitleaks are. What *is* useful to check in CI is
whether this lab's own scanner scripts still work: that every vulnerable
endpoint is still classified as vulnerable, and every fixed endpoint is
still classified as safe. A mismatch means the lab (demo app or detection
logic) broke, not that a real vulnerability was found.

Starts vulnerable_app.py, runs every registered class against both its
vulnerable and fixed endpoint, and writes any mismatches as findings in the
JSON shape scripts/summarize.py expects from its "sqli_lab" source.

Usage:
  python3 run_regression.py                        # human-readable only
  python3 run_regression.py --out sqli_lab.json     # also write findings JSON
  python3 run_regression.py --no-start-app          # assume the app is already running
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import requests

from auto_vuln_scanner import VULN_CLASSES, scan
from session_vuln_check import CLASSES

BASE_URL = "http://127.0.0.1:%s" % os.environ.get("VULN_APP_PORT", "5000")

# (class_name, vulnerable_path, vulnerable_base_params, safe_path, safe_base_params, fuzz_param)
SCANNER_CASES = [
    ("sqli", "/login", {"username": "zzz", "password": "zzz"}, "/login_safe", {"username": "zzz", "password": "zzz"}, "username"),
    ("xss", "/search", {"q": "zzz"}, "/search_safe", {"q": "zzz"}, "q"),
    ("cmdi", "/diag", {"host": "zzz"}, "/diag_safe", {"host": "zzz"}, "host"),
    ("traversal", "/file", {"name": "public.txt"}, "/file_safe", {"name": "public.txt"}, "name"),
    ("mass_assignment", "/signup", {"username": "zzz"}, "/signup_safe", {"username": "zzz"}, "is_admin"),
    ("ssrf", "/fetch_url", {"url": "https://example.invalid/"}, "/fetch_url_safe", {"url": "https://example.invalid/"}, "url"),
    (
        "account_enum",
        "/register",
        {"email": "brand-new-unused@example.com"},
        "/register_safe",
        {"email": "brand-new-unused2@example.com"},
        "email",
    ),
]

# (class_name, vulnerable-path overrides, safe-path overrides)
SESSION_CASES = [
    ("csrf", {"transfer_path": "/csrf_transfer"}, {"transfer_path": "/csrf_transfer_safe"}),
    ("idor", {"account_path": "/idor_account"}, {"account_path": "/idor_account_safe"}),
    ("deserialize", {"deserialize_path": "/deserialize"}, {"deserialize_path": "/deserialize_safe"}),
    (
        "stored_xss",
        {"post_path": "/review", "list_path": "/reviews"},
        {"post_path": "/review_safe", "list_path": "/reviews_safe"},
    ),
]

SESSION_DEFAULTS = {
    "transfer_path": "/csrf_transfer",
    "account_path": "/idor_account",
    "login_as": "alice",
    "target_id": 3,
    "deserialize_path": "/deserialize",
    "post_path": "/review",
    "list_path": "/reviews",
}


def _session_args(class_name: str, overrides: dict) -> argparse.Namespace:
    values = dict(SESSION_DEFAULTS)
    values["login_path"] = "/csrf_login" if class_name == "csrf" else "/idor_login"
    values.update(overrides)
    return argparse.Namespace(url=BASE_URL, **values)


def _path_from_overrides(overrides: dict) -> str:
    for key in ("transfer_path", "account_path", "deserialize_path", "post_path"):
        if key in overrides:
            return overrides[key]
    return "?"


def check_scanner_case(class_name, vuln_path, vuln_params, safe_path, safe_params, fuzz_param):
    vuln_class = VULN_CLASSES[class_name]
    findings = []
    for path, base_params, expect_vulnerable in (
        (vuln_path, vuln_params, True),
        (safe_path, safe_params, False),
    ):
        results = scan(f"{BASE_URL}{path}", base_params, [fuzz_param], vuln_class)
        got_vulnerable = bool(results)
        if got_vulnerable != expect_vulnerable:
            findings.append(
                {
                    "severity": "high",
                    "title": "regression: %s scanner misclassified %s" % (class_name, path),
                    "location": path,
                    "detail": "expected %s, got %s"
                    % ("VULNERABLE" if expect_vulnerable else "safe", "VULNERABLE" if got_vulnerable else "safe"),
                }
            )
    return findings


def check_session_case(class_name, vuln_overrides, safe_overrides):
    vuln_class = CLASSES[class_name]
    findings = []
    for overrides, expect_vulnerable in ((vuln_overrides, True), (safe_overrides, False)):
        args = _session_args(class_name, overrides)
        got_vulnerable, detail = vuln_class.check(args)
        if got_vulnerable != expect_vulnerable:
            path = _path_from_overrides(overrides)
            findings.append(
                {
                    "severity": "high",
                    "title": "regression: %s scanner misclassified %s" % (class_name, path),
                    "location": path,
                    "detail": "expected %s, got %s (%s)"
                    % ("VULNERABLE" if expect_vulnerable else "safe", "VULNERABLE" if got_vulnerable else "safe", detail),
                }
            )
    return findings


def wait_for_app(timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            requests.get(BASE_URL + "/login", timeout=1)
            return True
        except requests.RequestException:
            time.sleep(0.5)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="", help="write findings as JSON here (scripts/summarize.py 'sqli_lab' source)")
    ap.add_argument(
        "--no-start-app",
        action="store_true",
        help="assume vulnerable_app.py is already running on 127.0.0.1:5000 instead of starting it",
    )
    args = ap.parse_args()

    proc = None
    if not args.no_start_app:
        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve().parent / "vulnerable_app.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_for_app():
            print("vulnerable_app.py did not come up in time", file=sys.stderr)
            proc.terminate()
            return 2

    findings: list[dict] = []
    try:
        for case in SCANNER_CASES:
            findings.extend(check_scanner_case(*case))
        for case in SESSION_CASES:
            findings.extend(check_session_case(*case))
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)

    total_checks = len(SCANNER_CASES) + len(SESSION_CASES)
    if findings:
        print("%d regression(s) found in this lab's own scanners:" % len(findings))
        for item in findings:
            print("  [%s] %s: %s" % (item["severity"], item["title"], item["detail"]))
        return 1

    print(
        "OK: all %d classes classified correctly (%d endpoint checks)."
        % (total_checks, 2 * total_checks)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
