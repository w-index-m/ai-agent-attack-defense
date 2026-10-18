# LLM / AI agent defense checklist

日本語: [`llm-defense-checklist.ja.md`](llm-defense-checklist.ja.md)

An **actionable checklist** built from the "Prevent"/"Detect" items under the four patterns in
[`llm-target-attacks.en.md`](llm-target-attacks.en.md) (prompt injection, system prompt leakage,
indirect prompt injection, LLMjacking) — for checking whether your own system is protected.

> Same policy: **limited to checking detection/defense**. No attack reproduction.
> Some items will not apply to every environment (for example, pattern C does not apply to an LLM
> app that never ingests external content).
> **This is not an automated checker script.** A generic static analyzer would have too many false
> positives/negatives, and implementations differ too much between environments, so this stays a
> human checklist. That, too, is part of staying honest.

## A. Prompt injection → execution with the agent's privileges

- [ ] Agent-generated strings (tool arguments, prompt output) are **never passed directly** into shell commands or `eval`-style execution.
- [ ] Any **tool that takes a file path** (download, upload, read, write) **validates the path against an allowlist** so it cannot point outside the intended directory (the same hole as CVE-2026-25592's path traversal).
- [ ] Tool calls are **allowlisted**; the agent cannot call an arbitrary tool or command.
- [ ] The agent's execution environment runs with **least privilege** (containers as non-root, unneeded capabilities dropped, no host-wide write access).
- [ ] Risky actions (file deletion, outbound sending, access to credentials, payments) go through a **human approval gate**.
- [ ] You monitor for **unexpected child processes spawned from an agent process** (same idea as R7/R8).
- [ ] Paths that **receive instructions from outside** (an MCP server's custom instructions, plugin configuration) have an audit log of changes (G1, G4).

## B. System prompt leakage

- [ ] The system prompt **does not contain** credentials, internal URLs, other users' data, or anything else damaging if leaked.
- [ ] The design assumes **the system prompt can eventually leak** and causes no real harm if it does.
- [ ] An **output filter/check** looks for the system prompt appearing verbatim in responses.
- [ ] You can detect a pattern of queries from the same source, **slightly varied and repeated in a short window** (same idea as R3).

## C. Indirect prompt injection (via external content)

- [ ] External content the LLM ingests (email, web pages, documents, another tool's output) is **always treated as data, never as instructions** (the single most important item).
- [ ] There is a step that **strips hidden instructions** (HTML comments, white-on-white text, zero-width characters) from external content before it reaches the model.
- [ ] The destinations the LLM/agent can **send to (domains, tools, APIs) are allowlisted**; it cannot send to an arbitrary destination (applying R1/R4's idea to the agent's own outbound traffic).
- [ ] There is a check for whether **generated outbound links or email bodies contain parameters that look like sensitive data**.
- [ ] You can detect an LLM/agent service account **sending to a domain it does not normally use**.

## D. LLMjacking (theft and abuse of stolen cloud credentials)

- [ ] Cloud IAM is scoped to **least privilege, limited to the specific LLM services/models in use** (no broad `*` grants).
- [ ] Credentials are **not** kept in code or configuration files (confirmed with gitleaks or similar).
- [ ] **Budget alerts** are set on cloud LLM usage (inference call volume, cost).
- [ ] Cloud audit logs can detect **the act of disabling logging itself** (G4; see `llm-target-attacks.en.md` §5 for a real example, `DeleteModelInvocationLoggingConfiguration`).
- [ ] Unused API keys and credentials are **inventoried and revoked on a regular basis**.

## How to use this

- Revisit this **every time a new LLM app or agent is added**, not just once.
- For any unchecked item, see the corresponding pattern (A–D) in `llm-target-attacks.en.md` for a fuller explanation of prevention and detection.
- Connections to this repository's existing tools:
  - A (path validation, allowlisting) → review your own code with `patch_suggest.py`, `vuln_triage.html` (Semgrep ingestion)
  - A (audit logging) → the G1/G4 framework (`defense-detection-notes.en.md` §7)
  - D (credential inventory) → `gitleaks` (CI)
  - D (least-privilege cloud IAM) → the same remedy as step ⑥ of the Gambit chain (`defense-playbook.en.md`)

## Related files

- The four patterns in detail, with primary sources: [`llm-target-attacks.en.md`](llm-target-attacks.en.md)
- Dependency CVE checking: [`dep-cve-check-notes.md`](dep-cve-check-notes.md)
- Detection framework (R1–R8, G1–G6): [`defense-detection-notes.en.md`](defense-detection-notes.en.md)

> Limited to checking detection/defense. No attack reproduction.
