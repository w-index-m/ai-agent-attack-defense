#!/usr/bin/env python3
"""Scripted mock for OpenAI's Responses API, for testing `codex exec`
without a real LLM key. Protocol confirmed by reading codex's own Rust
source (codex-rs/codex-api/src/sse/responses.rs, codex-rs/protocol/src/
models.rs): codex ignores response.completed.response.output entirely
and instead reconstructs the turn's output purely from
response.output_item.done events, each carrying a ResponseItem
(internally tagged by "type", snake_case). response.created's own
response object can be empty ({}); response.completed only needs an
"id". Every event needs a numeric "sequence_number".

Script: turn 1 -> exec_command(cmd="pwd"), turn 2+ -> a final plain-text
message (no function_call item => codex ends the run)."""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/tmp/mock_llm/responses_requests.jsonl"
state = {"n": 0}


def sse(w, obj):
    data = ("data: " + json.dumps(obj) + "\n\n").encode()
    w.write(("%x\r\n" % len(data)).encode() + data + b"\r\n")
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
            f.write(json.dumps({"path": self.path, "body": req}, ensure_ascii=False) + "\n")

        state["n"] += 1
        n = state["n"]
        sys.stderr.write(f"\n=== turn {n}: POST {self.path} stream={req.get('stream')} ===\n")

        if not req.get("stream"):
            resp = {
                "id": "resp_mock_health", "object": "response", "created_at": 0,
                "status": "completed", "model": req.get("model", "mock"),
                "output": [{"type": "message", "id": "msg_health", "status": "completed",
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": "pong", "annotations": []}]}],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
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

        resp_id = f"resp_mock_{n}"
        real_turns_seen = sum(1 for line in open(LOG_PATH) if json.loads(line)["body"].get("stream"))
        seq = [0]

        def emit(obj):
            sse(self.wfile, {**obj, "sequence_number": seq[0]})
            seq[0] += 1

        emit({"type": "response.created", "response": {}})

        if real_turns_seen <= 1:
            sys.stderr.write("    -> scripted call: exec_command(cmd='pwd')\n")
            item = {
                "type": "function_call", "name": "exec_command",
                "arguments": json.dumps({"cmd": "pwd"}), "call_id": "call_mock_1",
            }
        else:
            text = "Mock run complete: no real analysis was performed."
            item = {"type": "message", "role": "assistant",
                    "content": [{"type": "output_text", "text": text}]}

        emit({"type": "response.output_item.done", "item": item})
        emit({"type": "response.completed", "response": {
            "id": resp_id,
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                      "input_tokens_details": {"cached_tokens": 0},
                      "output_tokens_details": {"reasoning_tokens": 0}},
        }})
        sse_end(self.wfile)


if __name__ == "__main__":
    open(LOG_PATH, "w").close()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8900
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    sys.stderr.write(f"responses mock listening on 0.0.0.0:{port}\n")
    srv.serve_forever()
