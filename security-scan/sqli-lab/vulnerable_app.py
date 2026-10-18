"""
Deliberately SQL-injectable demo app, for local/offline SQLi testing only.

Scope: run only against this app, on localhost, in an isolated sandbox.
Do not deploy this code anywhere reachable by anyone else.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
DB_PATH = "/tmp/sqli_lab.db"


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


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
