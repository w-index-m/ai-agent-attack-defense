# Threat model for security scanning

This repository is a **defensive** toolkit: detection rules, exposure checks, a
triage page, and small helper scripts. It contains no exploit code. Please keep
reports defensive too (see "Reports" below).

## What to test

Priority code (Python standard library only, plus one single-file HTML page):

- `netcheck/netcheck.py` — confirmation-only checker. It must refuse targets
  outside the allowed (private) ranges unless explicitly overridden.
- `scripts/zgrab2_guard.py` — allowlist guard in front of zgrab2. It must emit
  nothing and exit non-zero if any target is out of range.
- `scripts/patch_suggest.py` — turns scanner findings into proposed diffs. It
  must never write outside the repo root, never apply a patch without per-file
  confirmation, and never send secret values to the LLM.
- `scripts/summarize.py`, `scripts/os_patch_check_linux.py`,
  `scripts/os_patch_check_windows.py` — parse tool output and emit SARIF/NDJSON.
- `vuln_triage.html` — runs entirely in the browser and loads scanner output
  files (JSON, SARIF, JSON Lines).
- `.github/workflows/` — CI workflows (injection via untrusted input, token scope).

## Inputs to treat as adversarial

- Scanner report files loaded into `vuln_triage.html` (titles, messages, file
  paths, URLs may contain markup or script).
- Responses from scanned hosts read by `netcheck.py` / `zgrab2` output (banners,
  headers, redirects, very large or malformed responses).
- LLM output consumed by `patch_suggest.py` (diffs with path traversal, absolute
  paths, symlinks, huge hunks).
- Command output parsed by the OS update scripts.

## Out of scope

- Documentation, slide decks, and analysis notes (`security-scan/*.md`, `deck/`).
- Third-party tools analyzed in the notes (Strix, Cairn, Hermes, ARTEX,
  Semgrep, Trivy, gitleaks, ZAP) — report those to their own projects.
- `security-scan/strix-local-poc/` and `security-scan/cairn-lab/` (research
  material; lower priority).

## Severity rubric

- **Critical:** bypass of the target allowlist in `netcheck.py` or
  `zgrab2_guard.py` that leads to probing unauthorized hosts; arbitrary file write
  outside the repo via `patch_suggest.py`; code execution from a loaded report.
- **High:** script execution in `vuln_triage.html` from a crafted report file;
  secret values leaving the machine; patch application without confirmation.
- **Medium:** denial of service by crafted input; information disclosure of
  local paths.
- **Low:** hardening gaps with no demonstrated impact.

## Reports

- Please describe the finding, the location, the impact, and a **minimal** patch
  that fixes it. A merge-ready patch is welcome but not required.
- Proof-of-concepts should be the **smallest reproduction** that shows the bug
  (for example a crafted report file or a unit-test-style script). Do not produce
  weaponized exploits or attack tooling.
- Group findings by root cause; report one finding per root cause.
