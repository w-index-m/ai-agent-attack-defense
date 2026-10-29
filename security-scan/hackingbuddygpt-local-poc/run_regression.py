"""Regression/canary test for the dead-`api_base`-config finding in
ipa-lab/hackingBuddyGPT (see ../hackingbuddygpt-local-backend-notes.md) -- NOT a
vulnerability scan of this repository or of hackingBuddyGPT's users. This is not an
R-numbered detection rule: the bug isn't something attackers exploit, it's a
usability/config bug in a security tool, documented here mainly so it doesn't drift
out of date.

What this actually checks: that our documented finding about hackingBuddyGPT's
upstream source is still true *today*, against a fresh clone of its current `main`.
Three live mock-LLM-server runs against the real LiteLLM wrapper:

  1. `api_base` alone (no OPENAI_API_BASE env) -> expected to FAIL to reach the mock
     (the bug: this config field is dead). If this *succeeds* instead, upstream
     appears to have fixed it -- reported as a finding so the docs get revisited.
  2. `api_base` + OPENAI_API_BASE env -> expected to SUCCEED (the documented
     workaround). If this now fails too, something else changed upstream --
     reported as a finding.
  3. negative control (api_base correct, OPENAI_API_BASE unreachable) -> expected to
     FAIL, confirming OPENAI_API_BASE (not api_base) is what controls the
     destination. A surprise success here would mean the whole causal story needs
     re-checking -- reported as a finding.

A finding here means "our documentation about an *external* project's behavior is
stale," not "this repository has a vulnerability." Findings are written in the same
JSON shape scripts/summarize.py's sqli_lab source expects (severity/title/location),
reused here as the "hackingbuddygpt_regression" source.

Usage:
  python3 run_regression.py --hbgpt-src /path/to/hackingBuddyGPT/src
  python3 run_regression.py --hbgpt-src /path/to/hackingBuddyGPT/src --out hbgpt.json
  python3 run_regression.py --hbgpt-src /path/to/hackingBuddyGPT/src --mock-port 8900
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def start_mock_server(port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "mock_llm_server.py"), str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    return proc


def attempt(hbgpt_src: str, api_base: str, env_openai_base: str | None) -> tuple[bool, str]:
    """Runs one LiteLLM.get_response('ping') call in a subprocess (clean env per
    attempt) and returns (succeeded, detail)."""
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "from hackingBuddyGPT.utils.llm import LiteLLM\n"
        "llm = LiteLLM(api_key='dummy-mock-key', model='openai/mock-model', context_size=8000, api_base=%r)\n"
        "llm.init()\n"
        "print(llm.get_response('ping').answer)\n"
    ) % (hbgpt_src, api_base)
    env = dict(os.environ)
    env.pop("OPENAI_API_BASE", None)
    env.pop("OPENAI_BASE_URL", None)
    if env_openai_base:
        env["OPENAI_API_BASE"] = env_openai_base
    try:
        out = subprocess.run(
            [sys.executable, "-c", code], env=env,
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return False, "timed out"
    if out.returncode == 0:
        return True, out.stdout.strip()
    return False, (out.stderr or out.stdout).strip()[-300:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hbgpt-src", required=True, help="Path to a hackingBuddyGPT checkout's src/ directory")
    ap.add_argument("--mock-port", type=int, default=8900)
    ap.add_argument("--out", default="", help="write findings as JSON here (scripts/summarize.py 'hackingbuddygpt_regression' source)")
    args = ap.parse_args()

    mock_url = "http://127.0.0.1:%d/v1" % args.mock_port
    unreachable_url = "http://127.0.0.1:1/v1"

    proc = start_mock_server(args.mock_port)
    findings: list[dict] = []
    try:
        ok1, detail1 = attempt(args.hbgpt_src, mock_url, None)
        ok2, detail2 = attempt(args.hbgpt_src, mock_url, mock_url)
        ok3, detail3 = attempt(args.hbgpt_src, mock_url, unreachable_url)

        print("1) api_base only (expect FAIL):           %-4s  %s" % ("OK" if not ok1 else "SUCCEEDED", detail1[:80]))
        print("2) api_base + OPENAI_API_BASE (expect OK): %-4s  %s" % ("OK" if ok2 else "FAILED", detail2[:80]))
        print("3) negative control (expect FAIL):         %-4s  %s" % ("OK" if not ok3 else "SUCCEEDED", detail3[:80]))

        if ok1:
            findings.append({
                "severity": "medium",
                "title": "hackingBuddyGPT's api_base config appears FIXED upstream (was dead; see hackingbuddygpt-local-backend-notes.md)",
                "location": "hackingBuddyGPT/src/hackingBuddyGPT/utils/llm.py:LiteLLM.raw_completion",
                "detail": "api_base alone reached the mock server without OPENAI_API_BASE set -- re-verify and update the notes file; the documented workaround may no longer be necessary.",
            })
        if not ok2:
            findings.append({
                "severity": "high",
                "title": "hackingBuddyGPT mock-LLM wiring regressed: OPENAI_API_BASE workaround no longer reaches the mock server",
                "location": "hackingBuddyGPT/src/hackingBuddyGPT/utils/llm.py:LiteLLM.raw_completion",
                "detail": "api_base + OPENAI_API_BASE together used to succeed; this run failed: %s" % detail2,
            })
        if ok3:
            findings.append({
                "severity": "medium",
                "title": "hackingBuddyGPT api_base dead-config causal story needs re-checking",
                "location": "hackingBuddyGPT/src/hackingBuddyGPT/utils/llm.py:LiteLLM.raw_completion",
                "detail": "The negative control (correct api_base, unreachable OPENAI_API_BASE) unexpectedly succeeded -- api_base may no longer be fully inert.",
            })
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)

    if findings:
        print()
        print("%d regression(s) found (our documentation about hackingBuddyGPT may be stale):" % len(findings))
        for item in findings:
            print("  [%s] %s: %s" % (item["severity"], item["title"], item["detail"]))
    else:
        print()
        print("No regressions -- the documented bug and workaround both behave as recorded.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
