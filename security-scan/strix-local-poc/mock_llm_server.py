#!/usr/bin/env python3
"""Minimal OpenAI-compatible (streaming) mock LLM server for Strix local-backend
testing. Logs every request, and plays a short, fixed script so we can observe
the real tool-execution mechanics end-to-end without any real LLM: reply "OK"
to the connectivity preflight, run one real read-only shell command against the
sqli-lab target to reconfirm the SQLi auth bypass, call create_vulnerability_report
with that real evidence, then call finish_scan to end the run cleanly. The client
requests stream=true (SSE), so responses are sent as OpenAI-style streaming chunks.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/tmp/mock_llm/requests.jsonl"
state = {"n": 0}

RECON_CMD = (
    "curl -s 'http://127.0.0.1:5000/login?username=admin%27%20--&password=x'"
)

REPORT_ARGS = {
    "title": "SQL Injection Authentication Bypass in /login",
    "description": (
        "The `/login` endpoint builds its SQL query by directly interpolating "
        "the `username` and `password` request parameters into a string, with "
        "no parameterization or escaping. An attacker can inject SQL syntax "
        "into either field to alter the query's logic and bypass "
        "authentication entirely, without knowing any valid password."
    ),
    "target": "sqli-lab demo application, /login endpoint",
    "endpoint": "/login",
    "method": "GET",
    "impact": (
        "Any unauthenticated user can log in as an arbitrary existing "
        "account (including the admin account) without the correct "
        "password, and the same injection point could be extended to read "
        "or modify other data in the `users` table."
    ),
    "technical_analysis": (
        "The handler builds `query = f\"SELECT id, username, is_admin FROM "
        "users WHERE username = '{username}' AND password = '{password}'\"` "
        "and passes the resulting string straight to `conn.execute(query)`. "
        "Supplying `username=admin' --` closes the quoted string and starts "
        "a SQL line comment, so the query becomes "
        "`SELECT id, username, is_admin FROM users WHERE username = 'admin' "
        "--' AND password = 'x'` -- everything after `--` is commented out, "
        "so the password check never happens and the row for `admin` is "
        "returned regardless of the password supplied."
    ),
    "poc_description": (
        "1. Send a GET request to `/login` with `username` set to "
        "`admin' --` (URL-encoded) and any value for `password`.\n"
        "2. Observe the response returns HTTP 200 with `Login OK` and the "
        "admin account's row, instead of the HTTP 401 `Login failed` "
        "returned for a request with a non-existent username and a wrong "
        "password.\n"
        "3. Compare against a baseline request with an invalid username and "
        "password, which correctly returns `Login failed` (401), confirming "
        "the bypass is caused by the injected `--` comment and not by a "
        "generic application bug."
    ),
    "poc_script_code": (
        "curl -s 'http://127.0.0.1:5000/login?username=admin%27%20--&password=x'\n"
        "# -> 200 'Login OK ... Rows: [(3, 'admin', 1)]'\n\n"
        "curl -s 'http://127.0.0.1:5000/login?username=nope&password=nope'\n"
        "# -> 401 'Login failed'"
    ),
    "remediation_steps": (
        "Replace the string-interpolated query with a parameterized query "
        "that binds `username` and `password` as placeholders instead of "
        "formatting them into the SQL text, so the database driver treats "
        "them strictly as data and not as SQL syntax. The sibling "
        "`/login_safe` handler in this same file already does this "
        "correctly and can be used as the reference implementation."
    ),
    "evidence": (
        "Exploit request: GET /login?username=admin%27%20--&password=x -> "
        "HTTP 200, body: \"Login OK. Query was: SELECT id, username, "
        "is_admin FROM users WHERE username = 'admin' --' AND password = "
        "'x'\\nRows: [(3, 'admin', 1)]\".\n"
        "Baseline request: GET /login?username=nope&password=nope -> HTTP "
        "401, body: \"Login failed. Query was: SELECT id, username, "
        "is_admin FROM users WHERE username = 'nope' AND password = "
        "'nope'\"."
    ),
    "assumptions": (
        "None required -- the bypass was reproduced directly against the "
        "running target with no assumptions about hidden state."
    ),
    "counterevidence": (
        "Checked whether `admin` could simply log in with a blank or "
        "guessable password instead (which would mean this isn't really an "
        "auth bypass): the baseline request with a wrong, non-injected "
        "password for a real-looking username still correctly returns 401, "
        "so the bypass is specifically caused by the SQL comment syntax, "
        "not by a weak/absent password check."
    ),
    "confidence": "high",
    "severity_change_conditions": (
        "Would be lower if `/login` were already gated behind another "
        "authentication layer that this request could not reach; no such "
        "layer was observed in front of it."
    ),
    "fix_effort": "low",
    "cvss_breakdown": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "H",
        "availability": "N",
    },
    "cwe": "CWE-89",
    "code_locations": [
        {
            "path": "security-scan/sqli-lab/vulnerable_app.py",
            "start_line": 58,
            "end_line": 61,
            "label": "Build query via unsafe string interpolation",
            "fix_before": (
                "    query = (\n"
                "        f\"SELECT id, username, is_admin FROM users \"\n"
                "        f\"WHERE username = '{username}' AND password = "
                "'{password}'\"\n"
                "    )"
            ),
            "fix_after": (
                "    query = (\n"
                "        \"SELECT id, username, is_admin FROM users \"\n"
                "        \"WHERE username = ? AND password = ?\"\n"
                "    )"
            ),
        },
        {
            "path": "security-scan/sqli-lab/vulnerable_app.py",
            "start_line": 65,
            "end_line": 65,
            "label": "Pass params separately instead of as part of the query string",
            "fix_before": "        rows = conn.execute(query).fetchall()",
            "fix_after": "        rows = conn.execute(query, (username, password)).fetchall()",
        },
    ],
}

FINISH_ARGS = {
    "executive_summary": (
        "One finding was confirmed and filed: a SQL injection "
        "authentication bypass in /login, reproduced live against the "
        "running target. No real LLM reasoning was used -- this run is a "
        "scripted mock that re-confirms an already-known finding and "
        "exercises the real create_vulnerability_report/finish_scan tools."
    ),
    "methodology": (
        "Scripted mock LLM: ran one read-only HTTP request against /login "
        "to reconfirm the known SQLi auth bypass, filed it via "
        "create_vulnerability_report with real request/response evidence, "
        "then ended the scan."
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
        last_user = ""
        for m in reversed(req.get("messages", [])):
            if m.get("role") == "user":
                c = m.get("content")
                last_user = c if isinstance(c, str) else json.dumps(c)
                break
        sys.stderr.write(f"\n=== turn {n}: {len(tools)} tools; last user msg: {last_user[:200]!r} ===\n")

        if not req.get("stream"):
            # Non-streaming call (e.g. the connectivity preflight): plain JSON ChatCompletion.
            resp = {
                "id": f"chatcmpl-mock-{n}", "object": "chat.completion", "created": 0,
                "model": req.get("model", "mock-model"),
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "OK"},
                    "finish_reason": "stop",
                }],
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
            # The "Reply with just 'OK'" connectivity preflight: plain text, no tool call.
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "OK"}, "finish_reason": None}]})
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        else:
            real_turns_seen = sum(1 for line in open(LOG_PATH) if json.loads(line).get("tools"))
            if real_turns_seen <= 1:
                name, args = "exec_command", {"cmd": RECON_CMD}
            elif real_turns_seen == 2:
                name, args = "create_vulnerability_report", REPORT_ARGS
            else:
                name, args = "finish_scan", FINISH_ARGS
            sys.stderr.write(f"    -> scripted call: {name}({args})\n")

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
    open(LOG_PATH, "w").close()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write(f"mock LLM server listening on 127.0.0.1:{port}\n")
    srv.serve_forever()
