"""
Minimal, LLM-free IDOR/BOLA (Broken Object Level Authorization) checker.

Like CSRF, this doesn't fit auto_vuln_scanner.py's model (fuzz one GET
param with attack payloads, compare to a baseline): IDOR isn't about a
malformed value, it's about a *perfectly valid* object reference (another
user's own account id) that the server should, but doesn't, check belongs
to the caller. So this is a dedicated script:

1. Log in as a low-privilege user (alice, user_id=1).
2. Using alice's own session, request another user's account by id
   (e.g. user_id=3, admin) -- exactly what a normal user poking at the
   URL/API parameter would try.
3. Check whether the other user's private data comes back anyway.

Scope: run only against targets you own/control, e.g. vulnerable_app.py
in this same directory.
"""

from __future__ import annotations

import argparse
import sys

import requests

from auto_vuln_scanner import _is_allowed_target


def check(
    base_url: str, login_path: str, account_path: str, login_as: str, target_id: int
) -> tuple[bool, str]:
    s = requests.Session()

    login_resp = s.get(f"{base_url}{login_path}", params={"username": login_as}, timeout=10)
    if login_resp.status_code != 200:
        return False, f"login as {login_as!r} failed (status {login_resp.status_code}), cannot test"

    # Same session (own, valid login), but asking for a different user_id --
    # a normal authenticated request, no malicious payload involved.
    resp = s.get(f"{base_url}{account_path}", params={"user_id": target_id}, timeout=10)

    if resp.status_code == 200 and f"Account {target_id}" in resp.text:
        return True, f"accessed another user's account as {login_as!r}: {resp.text.strip()}"
    return False, f"access denied (status {resp.status_code}): {resp.text.strip()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="base URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--login-path", default="/idor_login")
    parser.add_argument("--account-path", default="/idor_account")
    parser.add_argument("--login-as", default="alice", help="the low-privilege user to log in as")
    parser.add_argument("--target-id", type=int, default=3, help="the other user's id to try to access")
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
    print(f"Login as: {args.login_as}  Account path: {args.account_path}  Target id: {args.target_id}")
    print("-" * 60)

    vulnerable, detail = check(args.url, args.login_path, args.account_path, args.login_as, args.target_id)
    if vulnerable:
        print(f"VULNERABLE: {detail}")
        return 1

    print(f"Not vulnerable (ownership enforced): {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
