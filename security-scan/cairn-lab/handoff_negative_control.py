"""Negative control for handoff_recheck_test.py: proves that the assertion in that
script is a meaningful check and not a tautology, by deliberately feeding worker B a
*stale* graph snapshot (fetched before worker A concluded) instead of a fresh one, and
confirming the marker is then correctly absent.

Usage:
    python3 handoff_negative_control.py [--cairn-src /path/to/Cairn/cairn/src] [--base-url http://127.0.0.1:8010]
"""

import argparse
import sys
import uuid


def run(base_url: str, cairn_src: str) -> None:
    sys.path.insert(0, cairn_src)
    from cairn.dispatcher.protocol.client import CairnClient
    from cairn.dispatcher.prompting import load_prompt, render_prompt

    client = CairnClient(base_url)
    marker_a = f"MARKER-A-{uuid.uuid4().hex[:8]}"

    res = client._request_json(
        "POST",
        "/projects",
        json={
            "title": "handoff-negative-control",
            "origin": "mock target (no network)",
            "goal": "prove the test catches a genuinely stale snapshot",
            "bootstrap_enabled": False,
        },
    )
    assert res.ok, res.text
    project_id = res.data["project"]["id"]

    # Snapshot taken BEFORE worker A concludes (simulates a scheduler that fetched
    # export_yaml too early / cached it across a handoff instead of refetching).
    stale_export = client.export_project(project_id)

    create_a = client.create_intent(project_id, from_ids=["origin"], description="worker A: investigate origin", creator="worker-a")
    intent_a_id = create_a.data["id"]
    client.heartbeat(project_id, intent_a_id, "worker-a")
    conclude_a = client.conclude(project_id, intent_a_id, "worker-a", f"worker A finding: {marker_a}")
    fact_a_id = conclude_a.data["fact"]["id"]

    # Build worker B's prompt using the deliberately STALE snapshot, not a fresh one.
    prompt_b = render_prompt(
        load_prompt("default", "explore.md"),
        {
            "graph_yaml": stale_export.strip(),
            "intent_id": "i002",
            "intent_description": f"worker B: follow up on {fact_a_id}",
        },
    )

    if marker_a in prompt_b:
        print("UNEXPECTED: stale snapshot somehow contains marker_a (test would not have caught a real staleness bug)")
    else:
        print(
            "EXPECTED: stale snapshot correctly does NOT contain marker_a -> this is exactly the failure mode "
            "handoff_recheck_test.py's assertion would flag as a BUG if Cairn's real scheduler ever fetched a "
            "stale export before dispatching a worker. Confirms that script's check is meaningful, not a tautology."
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cairn-src", default="Cairn/cairn/src", help="path to Cairn's cairn/src directory")
    parser.add_argument("--base-url", default="http://127.0.0.1:8010")
    args = parser.parse_args()
    run(args.base_url, args.cairn_src)
