#!/usr/bin/env python3
"""Minimal OpenAI-compatible (non-streaming) mock LLM server for
auto_vuln_scanner.py's --llm-class, scripted for OWASP Juice Shop's
Open Redirect / Allowlist Bypass challenge (/redirect?to=).

Unlike this repo's other mock_llm_server.py files (strix/cai/pentestgpt/
hackingbuddygpt), this one matches auto_vuln_scanner.py's own wire format
exactly, as documented in its ask_llm()/llm_propose_class():
  - plain (non-streaming) POST to {base_url}/chat/completions
  - response body shaped like a normal OpenAI chat completion, with the
    answer in choices[0].message.content
  - for --llm-class, that content must be ONE JSON object:
      {"payloads": [...], "detect": {"type": "<SAFE_DETECT_TYPES>", "marker": "..."}}

This is NOT a general-purpose LLM stand-in: it always returns the SAME
scripted answer, regardless of the vulnerability-class name it is asked
about. It does not "discover" anything. The payload/marker below were
confirmed by hand first (see security-scan/sqli-lab-coverage.ja.md /
deck/sqli-types-and-techniques.pptx, 2026-11-27):

  curl -i "http://127.0.0.1:3000/redirect?to=https://attacker.example/?x=https://github.com/juice-shop/juice-shop"
  -> HTTP/1.1 302 Found
     Location: https://attacker.example/?x=https://github.com/juice-shop/juice-shop
     body: "Found. Redirecting to https://attacker.example/..."

i.e. embedding an allow-listed URL inside the query string of an
attacker-controlled URL slips past Juice Shop's allowlist check. The
actual pass/fail judgment at scan time is still done by
auto_vuln_scanner.py's own reviewed, fixed code (_make_llm_detect's
reflected_marker path) -- this mock only supplies the payload string and
the marker to look for, exactly the way a real LLM response would, so the
end-to-end --llm-class mechanism can be exercised against a real target.

Usage:
    python3 mock_llm_server_juiceshop_open_redirect.py [port]   # default 11434

Then, against your own locally-run Juice Shop (bkimminich/juice-shop):
    python3 auto_vuln_scanner.py \\
        --url http://127.0.0.1:3000/redirect \\
        --baseline to=https://github.com/juice-shop/juice-shop \\
        --fuzz to \\
        --llm-class "Open Redirect (Allowlistバイパス)" \\
        --llm-url http://127.0.0.1:11434/v1 \\
        --i-own-this-target
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Confirmed by hand against a locally-run bkimminich/juice-shop, 2026-11-27 --
# see the curl output quoted above. Change these if your target's allowlist
# or redirect behavior differs; this script does not verify them itself.
PAYLOADS = [
    "https://attacker.example/?x=https://github.com/juice-shop/juice-shop",
]
MARKER = "attacker.example"

_calls = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[mock-llm-open-redirect] " + (fmt % args) + "\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            req = {}
        _calls.append(req)

        messages = req.get("messages") or []
        user_text = next((m.get("content", "") for m in reversed(messages) if m.get("role") == "user"), "")
        is_class_definition = "detect" in user_text.lower() or "vulnerability class to test for" in user_text.lower()

        if is_class_definition:
            content = json.dumps(
                {"payloads": PAYLOADS, "detect": {"type": "reflected_marker", "marker": MARKER}}
            )
        else:
            # --llm-payloads path: one payload string per line, no JSON.
            content = "\n".join(PAYLOADS)

        print(
            f"=== call {len(_calls)}: model={req.get('model')} "
            f"messages={len(messages)} -> scripted {'class-definition' if is_class_definition else 'payload-list'} reply",
            file=sys.stderr,
        )

        body = {
            "id": f"mock-{len(_calls)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.get("model", "mock-model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"mock llm ok (juiceshop open-redirect script)")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[mock-llm-open-redirect] listening on http://127.0.0.1:{port}/v1 (POST .../chat/completions)", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
