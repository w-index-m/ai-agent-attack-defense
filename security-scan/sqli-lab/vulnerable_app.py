"""
Deliberately vulnerable demo app (SQLi, reflected XSS, OS command
injection, path traversal, CSRF, IDOR/BOLA, insecure deserialization,
stored XSS, mass assignment, SSRF, account enumeration), for
local/offline testing only.

Scope: run only against this app, on localhost, in an isolated sandbox.
Do not deploy this code anywhere reachable by anyone else.
"""

import base64
import ipaddress
import json
import os
import pickle
import secrets as secrets_mod
import socket
import subprocess
import sqlite3
import threading
from urllib.parse import urlparse

import requests

# Ports are overridable so the lab can run on a host where 5000/5001 are taken
# (e.g. WSL2 mirrored networking shares ports with Windows services). Defaults are
# unchanged. Use the same values for the scanners (VULN_APP_PORT / VULN_INTERNAL_PORT).
APP_PORT = int(os.environ.get("VULN_APP_PORT", "5000"))
INTERNAL_PORT = int(os.environ.get("VULN_INTERNAL_PORT", "5001"))
from flask import Flask, request, session
from markupsafe import escape

app = Flask(__name__)
# Demo-only secret key, fine for a local lab; never do this in anything real.
app.secret_key = "sqli-lab-demo-key-not-for-production"
DB_PATH = "/tmp/sqli_lab.db"
DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER)"
    )
    conn.executemany(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
        [
            ("alice", "alice_pw_123", 0),
            ("bob", "bob_pw_456", 0),
            ("admin", "S3cretAdminPW!", 1),
        ],
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["GET"])
def login() -> tuple[str, int]:
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # VULNERABLE: user input concatenated directly into SQL string.
    query = (
        f"SELECT id, username, is_admin FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.OperationalError as exc:
        return f"SQL error: {exc}\nQuery was: {query}", 500
    finally:
        conn.close()

    if rows:
        return f"Login OK. Query was: {query}\nRows: {rows}", 200
    return f"Login failed. Query was: {query}", 401


@app.route("/login_safe", methods=["GET"])
def login_safe() -> tuple[str, int]:
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # FIXED: parameterized query, same behavior, not injectable.
    query = "SELECT id, username, is_admin FROM users WHERE username = ? AND password = ?"

    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(query, (username, password)).fetchall()
    finally:
        conn.close()

    if rows:
        return f"Login OK. Rows: {rows}", 200
    return "Login failed.", 401


@app.route("/search", methods=["GET"])
def search() -> tuple[str, int]:
    q = request.args.get("q", "")

    # VULNERABLE: user input reflected into HTML without escaping.
    return f"<html><body>Results for: {q}</body></html>", 200


@app.route("/search_safe", methods=["GET"])
def search_safe() -> tuple[str, int]:
    q = request.args.get("q", "")

    # FIXED: same behavior, but output is HTML-escaped before reflection.
    return f"<html><body>Results for: {escape(q)}</body></html>", 200


@app.route("/diag", methods=["GET"])
def diag() -> tuple[str, int]:
    host = request.args.get("host", "")

    # VULNERABLE: shell=True + string formatting lets shell metacharacters
    # (;, $(...), `...`, |) break out of the intended single command.
    cmd = f"echo Checking: {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return f"<pre>{result.stdout}{result.stderr}</pre>", 200


@app.route("/diag_safe", methods=["GET"])
def diag_safe() -> tuple[str, int]:
    host = request.args.get("host", "")

    # FIXED: no shell=True, host is passed as a single literal argument,
    # so shell metacharacters have no special meaning.
    result = subprocess.run(
        ["echo", "Checking:", host], shell=False, capture_output=True, text=True
    )
    return f"<pre>{result.stdout}{result.stderr}</pre>", 200


@app.route("/file", methods=["GET"])
def file_view() -> tuple[str, int]:
    name = request.args.get("name", "")

    # VULNERABLE: naive path concatenation, ../ escapes DOCS_DIR.
    path = os.path.join(DOCS_DIR, name)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f"<pre>{escape(f.read())}</pre>", 200
    except OSError as exc:
        return f"Error: {exc}", 404


@app.route("/file_safe", methods=["GET"])
def file_view_safe() -> tuple[str, int]:
    name = request.args.get("name", "")

    # FIXED: resolve the real path and reject anything that escapes DOCS_DIR.
    candidate = os.path.realpath(os.path.join(DOCS_DIR, name))
    if not candidate.startswith(os.path.realpath(DOCS_DIR) + os.sep):
        return "Access denied.", 403

    try:
        with open(candidate, encoding="utf-8", errors="replace") as f:
            return f"<pre>{escape(f.read())}</pre>", 200
    except OSError as exc:
        return f"Error: {exc}", 404


@app.route("/csrf_login", methods=["GET"])
def csrf_login() -> tuple[str, int]:
    # Establishes a logged-in session (cookie-based), like any normal login.
    session["user"] = "alice"
    session["balance"] = 100
    session["csrf_token"] = secrets_mod.token_hex(16)
    return f"Logged in as alice. Balance: {session['balance']}.", 200


@app.route("/csrf_transfer", methods=["POST"])
def csrf_transfer() -> tuple[str, int]:
    if "user" not in session:
        return "Not logged in.", 401

    # VULNERABLE: the only check is "is there a valid session cookie?".
    # A forged cross-site POST (e.g. an auto-submitting form on an attacker's
    # page) rides along with the browser's session cookie and succeeds too.
    amount = int(request.form.get("amount", request.args.get("amount", "0")))
    session["balance"] -= amount
    return f"Transferred {amount}. New balance: {session['balance']}.", 200


@app.route("/csrf_transfer_safe", methods=["POST"])
def csrf_transfer_safe() -> tuple[str, int]:
    if "user" not in session:
        return "Not logged in.", 401

    # FIXED: also requires a csrf_token that matches the one issued at
    # login time. A third-party page cannot read it (same-origin policy)
    # or guess it (random), so it cannot forge a valid request.
    token = request.form.get("csrf_token", request.args.get("csrf_token", ""))
    if not token or not secrets_mod.compare_digest(token, session.get("csrf_token", "")):
        return "CSRF token missing or invalid.", 403

    amount = int(request.form.get("amount", request.args.get("amount", "0")))
    session["balance"] -= amount
    return f"Transferred {amount}. New balance: {session['balance']}.", 200


# Private per-account data for the IDOR/BOLA demo, keyed by user id.
IDOR_ACCOUNTS = {
    1: {"username": "alice", "email": "alice@example.com", "private_note": "Alice's medical records are confidential."},
    2: {"username": "bob", "email": "bob@example.com", "private_note": "Bob's salary is $75,000."},
    3: {"username": "admin", "email": "admin@example.com", "private_note": "Admin recovery codes: 1234-5678"},
}


@app.route("/idor_login", methods=["GET"])
def idor_login() -> tuple[str, int]:
    username = request.args.get("username", "alice")
    uid = next((i for i, a in IDOR_ACCOUNTS.items() if a["username"] == username), None)
    if uid is None:
        return "Unknown user.", 404
    session["idor_user_id"] = uid
    return f"Logged in as {username} (user_id={uid}).", 200


@app.route("/idor_account", methods=["GET"])
def idor_account() -> tuple[str, int]:
    if "idor_user_id" not in session:
        return "Not logged in.", 401

    # VULNERABLE: returns whichever user_id is requested, with no check that
    # it belongs to the logged-in session -- the object reference (user_id)
    # alone is treated as authorization.
    requested_id = int(request.args.get("user_id", session["idor_user_id"]))
    account = IDOR_ACCOUNTS.get(requested_id)
    if not account:
        return "Not found.", 404
    return f"Account {requested_id}: {account}", 200


@app.route("/idor_account_safe", methods=["GET"])
def idor_account_safe() -> tuple[str, int]:
    if "idor_user_id" not in session:
        return "Not logged in.", 401

    # FIXED: enforce that the requested object actually belongs to the
    # logged-in session, instead of trusting the id alone.
    requested_id = int(request.args.get("user_id", session["idor_user_id"]))
    if requested_id != session["idor_user_id"]:
        return "Forbidden: you may only access your own account.", 403

    account = IDOR_ACCOUNTS[requested_id]
    return f"Account {requested_id}: {account}", 200


@app.route("/deserialize", methods=["POST"])
def deserialize() -> tuple[str, int]:
    body = request.get_data()

    # VULNERABLE: pickle.loads() on attacker-controlled bytes executes
    # arbitrary code during unpickling (via __reduce__), not just parses
    # data. This is remote code execution, not just a data-format bug.
    try:
        raw = base64.b64decode(body)
        obj = pickle.loads(raw)
    except Exception as exc:  # noqa: BLE001 - deliberately broad for the demo
        return f"Error: {exc}", 400
    return f"Deserialized object: {obj!r}", 200


@app.route("/deserialize_safe", methods=["POST"])
def deserialize_safe() -> tuple[str, int]:
    body = request.get_data()

    # FIXED: json.loads() only ever produces plain data (dict/list/str/
    # number/bool/None) -- there is no mechanism for it to execute code,
    # unlike pickle's object-reconstruction protocol.
    try:
        obj = json.loads(body)
    except Exception as exc:  # noqa: BLE001 - deliberately broad for the demo
        return f"Error: {exc}", 400
    return f"Deserialized object: {obj!r}", 200


# Stored XSS: separate storage per vulnerable/safe so the two never mix.
REVIEWS: list[str] = []
REVIEWS_SAFE: list[str] = []


@app.route("/review", methods=["POST"])
def review_post() -> tuple[str, int]:
    text = request.form.get("text", request.args.get("text", ""))
    REVIEWS.append(text)
    return "Review submitted.", 200


@app.route("/reviews", methods=["GET"])
def reviews_list() -> tuple[str, int]:
    # VULNERABLE: previously-stored input is reflected without escaping,
    # every time anyone views the list -- unlike reflected XSS, the
    # payload doesn't need to be in the victim's own request at all.
    items = "".join(f"<li>{r}</li>" for r in REVIEWS)
    return f"<ul>{items}</ul>", 200


@app.route("/review_safe", methods=["POST"])
def review_post_safe() -> tuple[str, int]:
    text = request.form.get("text", request.args.get("text", ""))
    REVIEWS_SAFE.append(text)
    return "Review submitted.", 200


@app.route("/reviews_safe", methods=["GET"])
def reviews_list_safe() -> tuple[str, int]:
    # FIXED: escaped at render time, same as the reflected-XSS fix.
    items = "".join(f"<li>{escape(r)}</li>" for r in REVIEWS_SAFE)
    return f"<ul>{items}</ul>", 200


# Mass assignment: separate storage per vulnerable/safe.
SIGNUP_ACCOUNTS: dict[str, dict] = {}
SIGNUP_ACCOUNTS_SAFE: dict[str, dict] = {}


@app.route("/signup", methods=["GET"])
def signup() -> tuple[str, int]:
    username = request.args.get("username", "")
    if not username:
        return "username required", 400

    # VULNERABLE: every submitted field is blindly bound onto the new
    # account, including ones the caller should never control (is_admin).
    account = dict(request.args)
    account.setdefault("is_admin", "false")
    SIGNUP_ACCOUNTS[username] = account
    return f"Account created: {account}", 200


@app.route("/signup_safe", methods=["GET"])
def signup_safe() -> tuple[str, int]:
    username = request.args.get("username", "")
    if not username:
        return "username required", 400

    # FIXED: explicit allowlist of bindable fields -- is_admin is never
    # settable by the caller no matter what they submit.
    account = {
        "username": username,
        "password": request.args.get("password", ""),
        "is_admin": "false",
    }
    SIGNUP_ACCOUNTS_SAFE[username] = account
    return f"Account created: {account}", 200


# SSRF: a second, "internal-only" service the main app can legitimately
# reach server-side, but which outside callers should never reach
# directly (think: a cloud metadata endpoint or an internal admin API).
def _run_internal_only_service() -> None:
    internal_app = Flask("internal_only_service")

    @internal_app.route("/latest/meta-data/secret-key")
    def secret() -> tuple[str, int]:
        return "INTERNAL-SECRET-KEY-DO-NOT-EXPOSE", 200

    internal_app.run(host="127.0.0.1", port=INTERNAL_PORT, use_reloader=False)


def _resolves_to_private_or_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return True
    return False


@app.route("/fetch_url", methods=["GET"])
def fetch_url() -> tuple[str, int]:
    url = request.args.get("url", "")

    # VULNERABLE: fetches whatever URL the caller supplies with no
    # restriction on scheme/host -- the server becomes a proxy an
    # attacker can use to reach otherwise-unreachable internal services.
    try:
        r = requests.get(url, timeout=3)
        return f"Fetched: {r.text[:500]}", 200
    except requests.RequestException as exc:
        return f"Fetch failed: {exc}", 502


@app.route("/fetch_url_safe", methods=["GET"])
def fetch_url_safe() -> tuple[str, int]:
    url = request.args.get("url", "")
    host = urlparse(url).hostname or ""

    # FIXED: refuse anything that resolves to loopback/private/link-local
    # addresses -- the classic SSRF-to-internal-service guard.
    if _resolves_to_private_or_loopback(host):
        return "Refused: internal/private address not allowed.", 403

    try:
        r = requests.get(url, timeout=3)
        return f"Fetched: {r.text[:500]}", 200
    except requests.RequestException as exc:
        return f"Fetch failed: {exc}", 502


# Account enumeration: separate storage per vulnerable/safe.
KNOWN_EMAILS = {"alice@example.com"}
KNOWN_EMAILS_SAFE = {"alice@example.com"}


@app.route("/register", methods=["GET"])
def register() -> tuple[str, int]:
    email = request.args.get("email", "")

    # VULNERABLE: a distinct error (and status code) reveals whether the
    # email is already registered, enabling account enumeration.
    if email in KNOWN_EMAILS:
        return "Error: this email is already registered.", 409
    KNOWN_EMAILS.add(email)
    return "Registration received.", 200


@app.route("/register_safe", methods=["GET"])
def register_safe() -> tuple[str, int]:
    email = request.args.get("email", "")

    # FIXED: identical response either way -- nothing observable reveals
    # whether the email was already registered.
    KNOWN_EMAILS_SAFE.add(email)
    return "If this email is valid, a confirmation has been sent.", 200


if __name__ == "__main__":
    threading.Thread(target=_run_internal_only_service, daemon=True).start()

    os.makedirs(DOCS_DIR, exist_ok=True)
    public_doc = os.path.join(DOCS_DIR, "public.txt")
    if not os.path.exists(public_doc):
        with open(public_doc, "w", encoding="utf-8") as f:
            f.write("This is a public document. Nothing sensitive here.\n")

    init_db()

    # VULN_APP_HOST: bind address for the main app only (defaults to loopback).
    # The internal-only service above always stays on 127.0.0.1 -- that is the
    # SSRF demo's whole premise (unreachable except from this process itself).
    bind_host = os.environ.get("VULN_APP_HOST", "127.0.0.1")
    app.run(host=bind_host, port=APP_PORT)
