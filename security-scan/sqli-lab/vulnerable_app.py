"""
Deliberately vulnerable demo app (SQLi, reflected XSS, OS command
injection, path traversal), for local/offline testing only.

Scope: run only against this app, on localhost, in an isolated sandbox.
Do not deploy this code anywhere reachable by anyone else.
"""

import os
import subprocess
import sqlite3

from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)
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


if __name__ == "__main__":
    os.makedirs(DOCS_DIR, exist_ok=True)
    public_doc = os.path.join(DOCS_DIR, "public.txt")
    if not os.path.exists(public_doc):
        with open(public_doc, "w", encoding="utf-8") as f:
            f.write("This is a public document. Nothing sensitive here.\n")

    init_db()
    app.run(host="127.0.0.1", port=5000)
