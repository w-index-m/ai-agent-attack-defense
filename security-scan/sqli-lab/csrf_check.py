"""
Minimal, LLM-free CSRF checker.

CSRF doesn't fit auto_vuln_scanner.py's model (fuzz one GET param, compare
to a baseline): it's about whether a state-changing request succeeds using
*only* an ambient session cookie, with no secret an attacker's page
couldn't also send. So this is a dedicated script:

1. Log in (get a session cookie).
2. Simulate a forged cross-site request: POST the state-changing action
   using *only* that session cookie, deliberately omitting any CSRF
   token (exactly what an attacker's auto-submitting form would send --
   it can set the amount, but it can't read or guess the token).
3. Check whether the action actually took effect (balance changed) even
   without a token.

Scope: run only against targets you own/control, e.g. vulnerable_app.py
in this same directory.
"""

from __future__ import annotations

import argparse
import sys

import requests

from auto_vuln_scanner import _is_allowed_target


def check(base_url: str, login_path: str, transfer_path: str) -> tuple[bool, str]:
    s = requests.Session()

    login_resp = s.get(f"{base_url}{login_path}", timeout=10)
    if login_resp.status_code != 200:
        return False, f"login failed (status {login_resp.status_code}), cannot test"

    # Forged request: same session cookie, no csrf_token at all -- this is
    # exactly what a cross-site auto-submitting form could produce.
    forged = requests.Session()
    forged.cookies.update(s.cookies)
    resp = forged.post(f"{base_url}{transfer_path}", data={"amount": "50"}, timeout=10)

    if resp.status_code == 200 and "Transferred" in resp.text:
        return True, f"forged request succeeded with no CSRF token: {resp.text.strip()}"
    return False, f"forged request was rejected (status {resp.status_code}): {resp.text.strip()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="base URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--login-path", default="/csrf_login")
    parser.add_argument("--transfer-path", default="/csrf_transfer")
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="override the localhost/RFC1918-only scope check",
    )
    args = parser.parse_args()

    if not args.i_own_this_target:
        allowed, reason = _is_allowed_target(args.url)
        if not allowed:
            print(f"Refusing to scan: {reason}", file=sys.stderr)
            return 2

    print(f"Target: {args.url}")
    print(f"Login: {args.login_path}  Transfer: {args.transfer_path}")
    print("-" * 60)

    vulnerable, detail = check(args.url, args.login_path, args.transfer_path)
    if vulnerable:
        print(f"VULNERABLE: {detail}")
        return 1

    print(f"Not vulnerable (CSRF token enforced): {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
