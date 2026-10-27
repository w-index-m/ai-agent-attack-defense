#!/usr/bin/env python3
"""Minimal OpenAI-compatible (streaming) mock LLM server for CAI (Cybersecurity AI
framework, aliasrobotics/cai), reusing the protocol worked out for Strix: CAI's
vendored agents SDK (cai.sdk.agents, same lineage as openai-agents) streams
chat-completion chunks over SSE with manual "Transfer-Encoding: chunked" framing.

Script: first tool-bearing turn -> generic_linux_command(command=<curl against
the sqli-lab target>), subsequent turns -> a final plain-text assistant message
with no tool_calls, which ends the agent's single-shot turn.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/tmp/cai_mock/requests.jsonl"
state = {"n": 0}

RECON_CMD = (
    "curl -s 'http://127.0.0.1:5000/login?username=admin%27%20--&password=x'"
)
FINAL_TEXT = (
    "Reconnaissance complete: the GET /login endpoint is vulnerable to SQL "
    "injection authentication bypass. Supplying username=admin' -- returns "
    "HTTP 200 with the admin row, confirming the bypass with no real LLM "
    "reasoning involved (scripted mock run)."
)


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
        last_user = ""
        for m in reversed(req.get("messages", [])):
            if m.get("role") == "user":
                c = m.get("content")
                last_user = c if isinstance(c, str) else json.dumps(c)
                break
        sys.stderr.write(
            f"\n=== turn {n}: path={self.path} stream={req.get('stream')} "
            f"{len(tools)} tools; last user msg: {last_user[:200]!r} ===\n"
        )

        if not req.get("stream"):
            real_turns_seen = sum(1 for line in open(LOG_PATH) if json.loads(line).get("tools"))
            if not tools:
                message = {"role": "assistant", "content": "OK"}
                finish_reason = "stop"
            elif real_turns_seen <= 1:
                name, args = "generic_linux_command", {"command": RECON_CMD}
                sys.stderr.write(f"    -> scripted call (non-stream): {name}({args})\n")
                message = {
                    "role": "assistant", "content": None,
                    "tool_calls": [{
                        "id": f"call_mock_{n}", "type": "function",
                        "function": {"name": name, "arguments": json.dumps(args)},
                    }],
                }
                finish_reason = "tool_calls"
            else:
                sys.stderr.write("    -> scripted call (non-stream): final message (no tool_calls)\n")
                message = {"role": "assistant", "content": FINAL_TEXT}
                finish_reason = "stop"

            resp = {
                "id": f"chatcmpl-mock-{n}", "object": "chat.completion", "created": 0,
                "model": req.get("model", "mock-model"),
                "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
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

        real_turns_seen = sum(1 for line in open(LOG_PATH) if json.loads(line).get("tools"))

        if not tools:
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "OK"}, "finish_reason": None}]})
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        elif real_turns_seen <= 1:
            name, args = "generic_linux_command", {"command": RECON_CMD}
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
        else:
            sys.stderr.write(f"    -> scripted call: final message (no tool_calls)\n")
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": FINAL_TEXT}, "finish_reason": None}]})
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})

        sse_raw(self.wfile, b"data: [DONE]\n\n")
        sse_end(self.wfile)


if __name__ == "__main__":
    open(LOG_PATH, "w").close()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write(f"mock LLM server listening on 127.0.0.1:{port}\n")
    srv.serve_forever()
