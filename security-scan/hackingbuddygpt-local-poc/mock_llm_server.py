#!/usr/bin/env python3
"""Minimal OpenAI-compatible mock LLM server for hackingBuddyGPT (via litellm).

Non-streaming Chat Completions. Logs every request's model + whether 'tools' was
present, and always returns a plain scripted text reply (no tool_calls) so this
also works for the plain-text LiteLLM.get_response() path.
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

_calls = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[mock] " + (fmt % args) + "\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            req = {}
        _calls.append(req)
        print(f"=== REQUEST RECEIVED (call {len(_calls)}) ===", file=sys.stderr)
        print(f"  path={self.path}", file=sys.stderr)
        print(f"  model={req.get('model')}", file=sys.stderr)
        print(f"  messages={len(req.get('messages', []))}", file=sys.stderr)
        print(f"  has tools={bool(req.get('tools'))}", file=sys.stderr)

        tools = req.get("tools") or []
        if tools:
            fn_name = tools[0]["function"]["name"]
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": fn_name,
                            "arguments": json.dumps({"title": "open-port", "content": "port 5000 is open (scripted)"}),
                        },
                    }
                ],
            }
            finish_reason = "tool_calls"
        else:
            message = {"role": "assistant", "content": f"MOCK-REPLY-{len(_calls)}: scripted response."}
            finish_reason = "stop"

        body = {
            "id": f"mock-{len(_calls)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.get("model", "mock-model"),
            "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
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
        self.wfile.write(b"mock llm ok")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = HTTPServer(("127.0.0.1", port), Handler)
    print(f"mock LLM server (hackingBuddyGPT/litellm) on 127.0.0.1:{port}", file=sys.stderr)
    srv.serve_forever()
