"""Re-check of Cairn's worker-to-worker handoff for the same class of "lost prior-turn
result" bug found in Strix (see ../mock-llm-framework-bug-hunting.md).

Calls Cairn's own CairnClient/prompting code directly against a real `cairn serve`
instance (no Docker worker containers, no real/mock LLM needed): worker A concludes an
Intent with a unique marker (producing a Fact), then this script builds worker B's
*actual* explore.md prompt the exact same way cairn.dispatcher.tasks.explore.run_explore_task
does, and checks that worker A's marker made it into worker B's prompt text.

Usage:
    python3 handoff_recheck_test.py <run-label> [--cairn-src /path/to/Cairn/cairn/src] [--base-url http://127.0.0.1:8010]

Requires a `cairn serve` instance already running at --base-url (see
cairn-authorized-lab-runbook.md section 4 for how to start one locally with a disposable
SQLite db; LLM/Docker are not needed for this script).
"""

import argparse
import sys
import uuid


def run_once(run_label: str, base_url: str, cairn_src: str) -> None:
    sys.path.insert(0, cairn_src)
    from cairn.dispatcher.protocol.client import CairnClient
    from cairn.dispatcher.prompting import load_prompt, render_prompt

    client = CairnClient(base_url)
    marker_a = f"MARKER-A-{uuid.uuid4().hex[:8]}"
    marker_b = f"MARKER-B-{uuid.uuid4().hex[:8]}"
    absent_marker = f"MARKER-ABSENT-{uuid.uuid4().hex[:8]}"  # never written anywhere

    res = client._request_json(
        "POST",
        "/projects",
        json={
            "title": f"handoff-test-{run_label}",
            "origin": "mock target (no network)",
            "goal": "chain a fact from worker A into worker B's prompt",
            "bootstrap_enabled": False,
        },
    )
    assert res.ok, res.text
    project_id = res.data["project"]["id"]
    print(f"[{run_label}] project={project_id}")

    # Worker A: create + claim + conclude an intent sourced from 'origin', producing Fact A.
    create_a = client.create_intent(project_id, from_ids=["origin"], description="worker A: investigate origin", creator="worker-a")
    assert create_a.ok, create_a.text
    intent_a_id = create_a.data["id"]

    hb_a = client.heartbeat(project_id, intent_a_id, "worker-a")
    assert hb_a.ok, hb_a.text

    conclude_a = client.conclude(project_id, intent_a_id, "worker-a", f"worker A finding: {marker_a}")
    assert conclude_a.ok, conclude_a.text
    fact_a_id = conclude_a.data["fact"]["id"]
    print(f"[{run_label}] worker A concluded intent={intent_a_id} -> fact={fact_a_id} marker={marker_a}")

    # ---- simulate what the scheduler does right before dispatching worker B's explore task ----
    export_after_a = client.export_project(project_id)

    assert marker_a in export_after_a, f"[{run_label}] BUG: marker_a not in export right after worker A concluded!"
    assert absent_marker not in export_after_a, f"[{run_label}] test sanity failure: absent_marker leaked in"
    print(f"[{run_label}] export after A: marker_a present, absent_marker correctly absent (sanity ok)")

    # Worker B: a *new* intent explicitly created "from" Fact A (the handoff), as the reason phase would.
    create_b = client.create_intent(project_id, from_ids=[fact_a_id], description=f"worker B: follow up on {fact_a_id}", creator="worker-b")
    assert create_b.ok, create_b.text
    intent_b_id = create_b.data["id"]

    hb_b = client.heartbeat(project_id, intent_b_id, "worker-b")
    assert hb_b.ok, hb_b.text

    # Build worker B's *actual* explore prompt exactly as run_explore_task does (minus the
    # container file write, which is just a pass-through of this same string).
    export_for_b_prompt = client.export_project(project_id)
    prompt_b = render_prompt(
        load_prompt("default", "explore.md"),
        {
            "graph_yaml": export_for_b_prompt.strip(),
            "intent_id": intent_b_id,
            "intent_description": f"worker B: follow up on {fact_a_id}",
        },
    )
    assert marker_a in prompt_b, f"[{run_label}] BUG: worker B's rendered prompt does NOT contain worker A's marker ({marker_a})! This is the lost-handoff bug."
    print(f"[{run_label}] worker B's rendered explore prompt DOES contain marker_a -> handoff intact")

    # Worker B concludes with its own marker, referencing fact A.
    conclude_b = client.conclude(project_id, intent_b_id, "worker-b", f"worker B finding (built on {fact_a_id}): {marker_b}")
    assert conclude_b.ok, conclude_b.text
    fact_b_id = conclude_b.data["fact"]["id"]
    print(f"[{run_label}] worker B concluded intent={intent_b_id} -> fact={fact_b_id} marker={marker_b}")

    final_export = client.export_project(project_id)
    assert marker_a in final_export and marker_b in final_export, f"[{run_label}] BUG: final export missing a marker"
    assert absent_marker not in final_export, f"[{run_label}] test sanity failure at end"

    # cross-check: intent B's "from" field in the export must literally list fact_a_id
    import yaml
    parsed = yaml.safe_load(final_export)
    intent_b_entry = next(i for i in parsed["intents"] if i["description"].startswith("worker B"))
    assert fact_a_id in intent_b_entry["from"], f"[{run_label}] BUG: intent B's recorded 'from' does not include fact A's id"
    print(f"[{run_label}] intent B's from-list correctly cites fact_a_id={fact_a_id}")

    print(f"[{run_label}] PASS - no lost-handoff bug observed\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("run_label", nargs="?", default="run")
    parser.add_argument("--cairn-src", default="Cairn/cairn/src", help="path to Cairn's cairn/src directory")
    parser.add_argument("--base-url", default="http://127.0.0.1:8010")
    args = parser.parse_args()
    run_once(args.run_label, args.base_url, args.cairn_src)
