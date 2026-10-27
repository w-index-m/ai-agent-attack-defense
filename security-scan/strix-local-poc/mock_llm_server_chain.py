#!/usr/bin/env python3
"""Strix-format mock LLM: a 2-vulnerability attack CHAIN instead of a single
finding. Step 1 (SSRF via /fetch_url) reaches an internal-only "metadata"
service and leaks a secret. Step 2 (IDOR via /idor_login + /idor_account)
logs in as a low-privilege user and pivots to read the admin account's
private data (recovery codes) -- a chain from SSRF-leaked internal access
to account-takeover-flavored IDOR, in one scripted scan.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/tmp/chain_mock/requests.jsonl"
state = {"n": 0}

SSRF_CMD = (
    "curl -s 'http://127.0.0.1:5000/fetch_url?url=http://127.0.0.1:5001/latest/meta-data/secret-key'"
)
IDOR_LOGIN_CMD = (
    "curl -s -c /tmp/idor_cookie.txt 'http://127.0.0.1:5000/idor_login?username=alice'"
)
IDOR_PIVOT_CMD = (
    "curl -s -b /tmp/idor_cookie.txt 'http://127.0.0.1:5000/idor_account?user_id=3'"
)

REPORT_ARGS = {
    "title": "Attack chain: SSRF-leaked internal secret + IDOR admin-account disclosure",
    "description": (
        "Two independently-exploitable issues chain together: (1) `/fetch_url` "
        "performs a server-side request to any attacker-supplied URL with no "
        "restriction on scheme or host (SSRF), reaching an internal-only "
        "metadata-style service on 127.0.0.1:5001 and leaking its secret; (2) "
        "`/idor_account` trusts a client-supplied `user_id` with no check that "
        "it belongs to the logged-in session (IDOR), letting a low-privilege "
        "user (alice) read the admin account's private data, including admin "
        "recovery codes."
    ),
    "target": "sqli-lab demo application, /fetch_url and /idor_account endpoints",
    "endpoint": "/fetch_url, /idor_login, /idor_account",
    "method": "GET",
    "impact": (
        "An unauthenticated or low-privilege attacker can (a) use the SSRF to "
        "reach internal-only services normally unreachable from outside, "
        "leaking secrets intended to stay internal, and separately (b) "
        "escalate from a throwaway low-privilege account to reading the "
        "admin account's private data (including its recovery codes) via "
        "IDOR -- a realistic path from external access toward full account "
        "takeover."
    ),
    "technical_analysis": (
        "`/fetch_url` calls `requests.get(url)` on the raw query parameter "
        "with no allowlist and no check against loopback/private/link-local "
        "addresses, so `url=http://127.0.0.1:5001/...` reaches the "
        "internal-only Flask app bound to 127.0.0.1:5001 and returns its "
        "response to the caller. Separately, `/idor_account` does "
        "`IDOR_ACCOUNTS.get(requested_id)` using a `user_id` query parameter "
        "with no comparison against `session['idor_user_id']`, so any "
        "logged-in session (even the lowest-privilege one) can read any "
        "other account's record, including the admin account (user_id=3)."
    ),
    "poc_description": (
        "1. SSRF: GET /fetch_url?url=http://127.0.0.1:5001/latest/meta-data/secret-key "
        "-- the internal-only service's secret is returned in the response, "
        "proving the app's own network position was used to reach a host "
        "the attacker could not reach directly.\n"
        "2. IDOR: log in as the low-privilege `alice` account via "
        "/idor_login, then GET /idor_account?user_id=3 using that same "
        "session -- the response is the `admin` account's record (including "
        "its private recovery codes), not alice's own account, proving the "
        "object reference alone was trusted as authorization."
    ),
    "poc_script_code": (
        "curl -s 'http://127.0.0.1:5000/fetch_url?url=http://127.0.0.1:5001/latest/meta-data/secret-key'\n"
        "# -> leaks the internal-only service's secret\n\n"
        "curl -s -c cookie.txt 'http://127.0.0.1:5000/idor_login?username=alice'\n"
        "curl -s -b cookie.txt 'http://127.0.0.1:5000/idor_account?user_id=3'\n"
        "# -> returns the admin account's private_note (recovery codes), while logged in as alice"
    ),
    "remediation_steps": (
        "For the SSRF: validate the target of `/fetch_url` against an "
        "allowlist, and explicitly reject URLs resolving to loopback/"
        "private/link-local addresses, as the sibling `/fetch_url_safe` "
        "handler already does. For the IDOR: compare the requested "
        "`user_id` against `session['idor_user_id']` and reject mismatches, "
        "as the sibling `/idor_account_safe` handler already does."
    ),
    "evidence": (
        "SSRF: GET /fetch_url?url=http://127.0.0.1:5001/latest/meta-data/secret-key "
        "returned the internal-only service's secret value.\n"
        "IDOR: logged in as alice (user_id=1) via /idor_login, then GET "
        "/idor_account?user_id=3 returned the admin account's record "
        "(username=admin, private_note containing admin recovery codes) "
        "under alice's own session -- not alice's own account."
    ),
    "assumptions": "None required -- both steps were reproduced directly against the running target.",
    "counterevidence": (
        "Checked that /idor_account?user_id=1 (alice's own id) under the "
        "same session correctly returns alice's own record, confirming the "
        "endpoint does distinguish accounts by id -- the bug is specifically "
        "that it never checks the id against the session owner, not that "
        "the endpoint is broken in some unrelated way."
    ),
    "confidence": "high",
    "severity_change_conditions": (
        "Would be lower if the internal-only service on :5001 held no "
        "sensitive data, or if idor_login required proof of account "
        "ownership rather than a bare username."
    ),
    "fix_effort": "low",
    "cvss_breakdown": {
        "attack_vector": "N", "attack_complexity": "L", "privileges_required": "L",
        "user_interaction": "N", "scope": "C",
        "confidentiality": "H", "integrity": "N", "availability": "N",
    },
    "cwe": "CWE-918",
    "code_locations": [
        {
            "path": "security-scan/sqli-lab/vulnerable_app.py",
            "start_line": 381, "end_line": 383,
            "label": "SSRF: unrestricted outbound request in /fetch_url",
            "fix_before": (
                "    try:\n"
                "        r = requests.get(url, timeout=3)\n"
                "        return f\"Fetched: {r.text[:500]}\", 200"
            ),
            "fix_after": (
                "    if _resolves_to_private_or_loopback(urlparse(url).hostname or \"\"):\n"
                "        return \"Fetch refused: target resolves to an internal address\", 400\n"
                "    r = requests.get(url, timeout=3)\n"
                "    return f\"Fetched: {r.text[:500]}\", 200"
            ),
        },
        {
            "path": "security-scan/sqli-lab/vulnerable_app.py",
            "start_line": 227, "end_line": 227,
            "label": "IDOR: no ownership check in /idor_account",
            "fix_before": "    account = IDOR_ACCOUNTS.get(requested_id)",
            "fix_after": (
                "    if requested_id != session[\"idor_user_id\"]:\n"
                "        return \"Forbidden: you may only access your own account.\", 403\n"
                "    account = IDOR_ACCOUNTS.get(requested_id)"
            ),
        },
    ],
}

FINISH_ARGS = {
    "executive_summary": (
        "One chained finding was confirmed and filed: an SSRF in /fetch_url "
        "reaching an internal-only service, combined with an IDOR in "
        "/idor_account letting a low-privilege session read the admin "
        "account's private data. Both steps were reproduced live. Scripted "
        "mock run (no real LLM reasoning)."
    ),
    "methodology": (
        "Scripted mock LLM: (1) used /fetch_url to reach the internal-only "
        "service and leak its secret, (2) logged in as a low-privilege "
        "account and used /idor_account to pivot to the admin account's "
        "data, (3) filed the chained finding via create_vulnerability_report, "
        "(4) ended the scan."
    ),
    "technical_analysis": "See the filed vulnerability report for details.",
    "recommendations": "See the filed vulnerability report's remediation steps.",
}


def sse_chunk(w, obj):
    data = ("data: " + json.dumps(obj) + "\n\n").encode()
    w.write(("%x\r\n" % len(data)).encode() + data + b"\r\n")
    w.flush()


def sse_raw(w, raw_bytes):
    w.write(("%x\r\n" % len(raw_bytes)).encode() + raw_bytes + b"\r\n")
    w.flush()


def sse_end(w):
    w.write(b"0\r\n\r\n")
    w.flush()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            req = {"_raw": body.decode(errors="replace")}

        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(req, ensure_ascii=False) + "\n")

        state["n"] += 1
        n = state["n"]
        tools = req.get("tools", [])
        sys.stderr.write(f"\n=== turn {n}: {len(tools)} tools, stream={req.get('stream')} ===\n")

        if not req.get("stream"):
            resp = {
                "id": f"chatcmpl-mock-{n}", "object": "chat.completion", "created": 0,
                "model": req.get("model", "mock-model"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
            payload = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        base = {"id": f"chatcmpl-mock-{n}", "object": "chat.completion.chunk", "created": 0,
                "model": req.get("model", "mock-model")}

        if not tools:
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "OK"}, "finish_reason": None}]})
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        else:
            real_turns_seen = sum(1 for line in open(LOG_PATH) if json.loads(line).get("tools"))
            # 5-step script: SSRF -> IDOR login -> IDOR pivot -> report -> finish
            if real_turns_seen == 1:
                name, args = "exec_command", {"cmd": SSRF_CMD}
            elif real_turns_seen == 2:
                name, args = "exec_command", {"cmd": IDOR_LOGIN_CMD}
            elif real_turns_seen == 3:
                name, args = "exec_command", {"cmd": IDOR_PIVOT_CMD}
            elif real_turns_seen == 4:
                name, args = "create_vulnerability_report", REPORT_ARGS
            else:
                name, args = "finish_scan", FINISH_ARGS
            sys.stderr.write(f"    -> scripted call ({real_turns_seen}): {name}\n")

            call_id = f"call_mock_{n}"
            sse_chunk(self.wfile, {**base, "choices": [{
                "index": 0,
                "delta": {"role": "assistant", "tool_calls": [{
                    "index": 0, "id": call_id, "type": "function",
                    "function": {"name": name, "arguments": ""},
                }]},
                "finish_reason": None,
            }]})
            sse_chunk(self.wfile, {**base, "choices": [{
                "index": 0,
                "delta": {"tool_calls": [{"index": 0, "function": {"arguments": json.dumps(args)}}]},
                "finish_reason": None,
            }]})
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})

        sse_raw(self.wfile, b"data: [DONE]\n\n")
        sse_end(self.wfile)


if __name__ == "__main__":
    import os
    os.makedirs("/tmp/chain_mock", exist_ok=True)
    open(LOG_PATH, "w").close()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write(f"chain mock listening on 127.0.0.1:{port}\n")
    srv.serve_forever()
