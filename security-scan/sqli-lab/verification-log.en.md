# sqli-lab Verification Summary (2026-10-25)

日本語: [`verification-log.ja.md`](verification-log.ja.md)

Summary of two pieces of work against `security-scan/sqli-lab/` (the repo's intentionally
vulnerable Flask demo app):

1. A feature added for the user's own WSL environment (`VULN_APP_HOST`, already merged)
2. Hands-on verification of all 9 vulnerability classes, run inside this session's sandbox
   (no repo changes -- verification record only)

## 1. Feature added: `VULN_APP_HOST` environment variable (merged, PR #65)

### Problem

To make `vulnerable_app.py` listen on a specific IP in WSL (e.g. the WSL instance's
eth0 address), the file had to be hand-edited with `sed` every time:
```bash
sed -i 's/host="127.0.0.1", port=5000/host="0.0.0.0", port=5000/' vulnerable_app.py
```

### Change

The main app's bind address is now read from an environment variable, defaulting to the
previous `127.0.0.1`:
```python
bind_host = os.environ.get("VULN_APP_HOST", "127.0.0.1")
app.run(host=bind_host, port=5000)
```

The SSRF demo's internal-only service (port 5001) stays hardcoded to `127.0.0.1` on
purpose -- being unreachable from outside is the entire premise of that demo.

### Usage

```bash
python3 vulnerable_app.py                              # default: 127.0.0.1 only
VULN_APP_HOST=172.25.212.244 python3 vulnerable_app.py  # listen on that IP (no sed needed)
```

## 2. Hands-on verification of all 9 vulnerability classes (sandbox, record only)

Each vulnerability class `security-scan/sqli-lab/` reproduces was actually exploited
against its vulnerable/fixed endpoint pair, to confirm the difference in behavior.
Detailed client-side and server-side logs, plus how SQL actually executes under the
hood, were delivered separately as a more detailed report; this is the condensed
summary of results.

| # | Class | What was tried | Result |
|---|---|---|---|
| 1 | **sqli** (SQL injection) | `username=admin' --` to comment out the password check | **Succeeded.** Logged in as admin (is_admin=1) with no password. Independently confirmed a real SQLite engine is involved by opening `/tmp/sqli_lab.db` directly. |
| 2 | **cmdi** (OS command injection) | Shell metacharacters like `host=x; id` | **Succeeded.** `id` command output leaked into the response. |
| 3 | **ssrf** (server-side request forgery) | Reached the internal-only service (port 5001) via `/fetch_url` | **Succeeded.** Retrieved `INTERNAL-SECRET-KEY-DO-NOT-EXPOSE` from outside. |
| 4 | **traversal** (path traversal) | `../../../../etc/passwd` | **Succeeded.** Contents of `/etc/passwd` returned verbatim. |
| 5 | **xss** (reflected XSS) | `<script>alert(1)</script>` | **Succeeded.** Tag reflected unescaped. |
| 6 | **stored_xss** | Injected a script into a posted comment | **Succeeded.** Persistent XSS affecting every subsequent viewer. |
| 7 | **mass_assignment** | Added `is_admin=true` to a signup request | **Succeeded.** The attacker-supplied privilege flag was accepted as-is. |
| 8 | **idor** (IDOR/BOLA) | Logged in as alice, requested `user_id=3` (admin) | **Succeeded.** Retrieved admin's private note (recovery codes). |
| 9 | **account_enum** | Compared responses for a registered vs. unregistered email | **Succeeded.** The response difference reveals whether an email is registered. |
| 10 | **deserialize** (insecure deserialization -> RCE) | A crafted pickle payload running `os.system()` | **Succeeded (highest impact).** Actual OS command execution confirmed -- the output of `uid=0(root)...` was written to a file (the sandbox process ran as root). |
| 11 | **csrf** | A real browser (Playwright/Chromium) visiting an attacker page on a different origin, which auto-submitted a forged form | **Succeeded.** The victim's balance dropped from 100 to 50 just from opening the trap page. The fixed endpoint correctly rejected the same attack with a 403 (CSRF token mismatch). |

In every case, the `_safe`-suffixed fixed endpoint correctly rejected or neutralized the
same payload.

### Two technically interesting findings

1. **Only the `sqli` class actually uses a real SQL engine.** The other 10 classes are
   reproduced with in-memory dicts/lists/sets, which independently confirms they are a
   different kind of vulnerability (missing authorization, missing escaping, etc.), not
   SQL injection by another name.

2. **`SameSite=Lax` alone does not stop this CSRF.** The session cookie was set with
   `SameSite=Lax`, yet the trap page's auto-submitting `<form method="POST">` (treated
   as a top-level navigation) still carried the cookie, and the attack succeeded.
   Switching to `Strict` can break legitimate cross-site navigation, so an explicit
   CSRF-token defense is still necessary -- confirmed hands-on rather than just
   asserted.

## Notes

- All verification ran inside this session's cloud sandbox (separate from the user's
  WSL environment), against `127.0.0.1` only.
- No code changes were made to the repository beyond the `VULN_APP_HOST` feature.
  The verification itself was limited to confirmation/recording; no attack procedure
  was generalized or turned into reusable tooling.
