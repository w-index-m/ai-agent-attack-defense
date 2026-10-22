# security-scan — index (English)

日本語版は [`README.ja.md`](README.ja.md) / Japanese index: see `README.ja.md`.

A defensive research, detection, and governance bundle built around the AI-agent
attack harnesses from the Gambit Security report (2026-09-22): **Strix / Cairn / Hermes**.
**Detection and defense design only** — no attack execution steps, no safety-bypass
techniques. Use only against assets you own or are authorized to test.

## Start here

- **[`dashboard.html`](dashboard.html)** — integrated dashboard (open in a browser,
  offline, no external calls): landscape of offensive AI agents → detection coverage →
  preventive controls → CVP tiers → asset links.
- **[`local-vuln-testing-walkthrough.ja.md`](local-vuln-testing-walkthrough.ja.md)** (JA) — entry
  point for trying vulnerability checks on your own PC: inventory with netcheck → a self-hosted
  practice target (DVWA/Juice Shop) → automated scanning with Strix + a local LLM, with links to
  each step.

## Documents

Grown past 25 files, so it's grouped by theme below. For the formal definition of the detection
tags (R1–R11, G1–G6), see [`../shared/taxonomy.json`](../shared/taxonomy.json).

### Overview / summary

| File | Contents |
|---|---|
| [`security-summary.en.md`](security-summary.en.md) (EN) / [`.ja.md`](security-summary.ja.md) (JA) | **Security summary**: the seven attack steps and their defenses, known vulnerabilities, what a company should do, what was built, verification status (honestly), and next steps. Start here. |
| [`defense-playbook.en.md`](defense-playbook.en.md) (EN) / [`.ja.md`](defense-playbook.ja.md) (JA) | **Defense playbook for AI-agent attacks**: what Strix / Cairn / Hermes / ARTEX look like, then prevent / detect / respond / verify for each of the seven chain steps, incident flow, a honeytoken design memo, a first-week plan, and an explicit **not-implemented list**. |
| [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md) (JA) | The four defense layers (prevent / detect / respond / recover) and how an external rollout-roadmap proposal maps onto them: assessment, cautions, and the gaps this repo fills. Clarifies R1–R8 vs ③, with a kernel-FIM primer. |
| [`glossary.ja.md`](glossary.ja.md) (JA) | Plain-language glossary: FIM / CSP / WORM / egress / C2 / RCE / IAM and more, one line each. Grows as new terms come up. |

### AI agents as the attacker (the Gambit lineage: Strix / Cairn / Hermes / ARTEX)

| File | Contents |
|---|---|
| [`defense-detection-notes.md`](defense-detection-notes.md) (JA) / [`.en.md`](defense-detection-notes.en.md) (EN) | Cross-tool defense & detection notes: SOC operational layer (data-source mapping, detection rules R1–R8, MITRE ATT&CK, triage) and the broader offensive-AI-agent landscape. |
| [`artex-analysis.en.md`](artex-analysis.en.md) (EN) / [`.ja.md`](artex-analysis.ja.md) (JA) | Defensive analysis of the autonomous AI pentest agent **ARTEX** (static primary-source review): architecture decomposition + R1–R8/G1–G6 mapping. No attack procedures. |
| [`unit42-ai-assisted-intrusion.en.md`](unit42-ai-assisted-intrusion.en.md) / [`.ja.md`](unit42-ai-assisted-intrusion.ja.md) (JA) | Analysis of Unit 42's real-incident report "An AI-Assisted Cyber Attack." A human attacker automated an intrusion with frontier AI agents, compressing ~2 weeks of work into under 10 hours. Includes Unit 42's MITRE ATT&CK×ATLAS mapping and connections to this repo's R1–R8/G1–G6. |
| [`jp-advisory-mapping.en.md`](jp-advisory-mapping.en.md) (EN) / [`.ja.md`](jp-advisory-mapping.ja.md) (JA) | **Mapping of the October 2026 Japanese advisories (JPCERT/CC, Personal Information Protection Commission, others) to this repository**: API abuse, known-vulnerability exploitation (including BI tools), admin misconfiguration, and web shells, with prevention, detection, and gaps for each. Based on secondary information; confirm in the primary sources. |
| [`fortimanager-peerstitch-notes.en.md`](fortimanager-peerstitch-notes.en.md) / [`.ja.md`](fortimanager-peerstitch-notes.ja.md) (JA) | **[No AI involvement]** Analysis of Unit 42's real-incident report on "PEERSTITCH." A FortiManager vulnerability (CVE-2024-47575) cascaded into a compromise of 500+ FortiGate firewalls, plus a technical breakdown of the memory-resident implant. Connects to Gambit chain step ⑥ (over-broad permissions). Included as a contrasting no-AI case. |
| [`strix-local-backend-notes.md`](strix-local-backend-notes.md) | Strix execution-flow analysis and a Docker-free local backend design. |
| [`strix-local-poc/`](strix-local-poc/) | PoC for the above (patch, verification scripts, results). |
| [`cairn-lab/`](cairn-lab/) | Runbook and real config for running Cairn in an authorized, isolated lab; plus a no-attack mock config. |
| [`strix-local-poc/windows-wsl-ollama-setup.md`](strix-local-poc/windows-wsl-ollama-setup.md) (JA) | Hands-on Windows 11 + WSL2 + local-Ollama setup to run Strix with no cloud LLM cost, against a self-hosted practice target (e.g. DVWA), plus Groq/OpenRouter cloud-LLM attempts and a Claude Code cloud-sandbox attempt. **Final conclusion: abandoned.** Every configuration tried — 3 local model sizes, Groq, OpenRouter, a cloud sandbox — hit a different structural wall (malformed tool-call JSON/command loops, a free-tier token-per-minute cap, an unresolved 404 on large requests, or a network allowlist blocking every LLM provider). Includes a PowerShell launcher ([`start-strix-test.ps1`](strix-local-poc/start-strix-test.ps1)) that automates the setup steps, now a historical record. |
| [`sqli-lab/README.ja.md`](sqli-lab/README.ja.md) (JA) | **What replaced the Strix PoC.** A minimal Flask+SQLite app with vulnerable/fixed endpoint pairs for 11 classes (SQLi, reflected + stored XSS, OS command injection, path traversal, CSRF, IDOR/BOLA, insecure-deserialization RCE, mass assignment, SSRF, account enumeration — the last 4 added after cross-checking against a third party's real Strix run), plus two LLM-free rule-based scripts (`auto_vuln_scanner.py` for GET-param-fuzzable classes, `session_vuln_check.py` for session/payload-shaped ones) and a one-command runner (`scan_all.sh`). No LLM, no agent loop, no Docker. Scoped to localhost/RFC1918 by default (same guard as netcheck). Also includes `run_regression.py`, wired into the CI scan as a regression test (not a vulnerability-scan gate, since `vulnerable_app.py` is intentionally-vulnerable demo code, not this repo's own) — it asserts every vulnerable/fixed endpoint still classifies correctly and reports mismatches via `summarize.py`'s new `sqli_lab` source. |

### [Scope expansion] LLM systems as the target

| File | Contents |
|---|---|
| [`llm-target-attacks.en.md`](llm-target-attacks.en.md) / [`.ja.md`](llm-target-attacks.ja.md) (JA) | **Attacks on LLM systems themselves** (prompt injection, system prompt leakage, indirect prompt injection, LLMjacking, and **abuse of multi-agent sessions** — five patterns), organized from primary sources. Notes connection points to the existing R1–R8/G1–G6 (patterns C/D/E are implemented as R9–R11). Also covers Unit 42's CrewAI/AutoGen study, its large-scale web-based IDPI study, the GCP Vertex AI "Double Agents" case, and Agent Session Smuggling (A2A protocol). |
| [`openclaw-skill-supply-chain.en.md`](openclaw-skill-supply-chain.en.md) / [`.ja.md`](openclaw-skill-supply-chain.ja.md) (JA) | Two Unit 42 primary sources on the AI agent **OpenClaw**'s skill marketplace **ClawHub**: confirmed malicious skills (infostealers, scanner evasion, agent-specific financial schemes) and a registry-wide Behavioral Integrity Verification (BIV) study (80% of 49,943 skills showed a declared-vs-actual deviation). |
| [`llm-defense-checklist.en.md`](llm-defense-checklist.en.md) / [`.ja.md`](llm-defense-checklist.ja.md) (JA) | A checklist, derived from `llm-target-attacks.en.md`'s five patterns, for checking whether **your own system** is protected. Intentionally a human checklist, not an automated script. |

### Detection rule implementations

| File | Contents |
|---|---|
| [`detections/`](detections/) | Detection rule implementations: Sigma / Falco / Datadog (R1–R8, the Gambit lineage) + Sigma / Datadog (R9–R11, LLM-target-attacks patterns C/D/E) + Sigma / Datadog (R12, DNS water torture / random-subdomain-attack detection — general infra-availability signal, not AI-agent-specific) + Sigma / Datadog (R13, the real-world "wp2shell" WordPress REST-API-batch-endpoint exploitation chain — CVE-2026-63030 route confusion + CVE-2026-60137 SQLi leading to webshell placement, notably *discovered* via AI-assisted source auditing and now actively exploited in the wild) + Sigma / Datadog (R14, the real-world eMudhra intermediate-CA private-key compromise, October 2026 — detects TLS clients whose trust store hasn't yet dropped the 8 revoked intermediates, a general PKI-trust signal rather than an AI-agent-specific one) + Sigma / Datadog (R16/R17, real-world critical CVEs in the two most common web server daemons themselves — Apache httpd's mod_http2 double-free, CVE-2026-23918, and Nginx's ngx_http_rewrite_module overflow, CVE-2026-42945 a.k.a. "NGINX Rift" — detected via worker-crash patterns and version-banner leads, neither of which is proof alone; `sqli-lab`'s scanners carry the same version-range checks) + Sigma / Datadog (R18/R19, two classic but still-current internet-background-noise RCE patterns in the PHP ecosystem — PHPUnit's `eval-stdin.php` reachable via an exposed `/vendor/` directory, CVE-2017-9841, and ThinkPHP's `invokefunction`/`call_user_func_array` RCE, CVE-2018-20062/CVE-2019-9082 — both CISA KEV-listed and detectable from plain URI string matching, unlike R16/R17; unrelated to PHP2Shell despite the PHP connection). Tune thresholds/allowlists per environment. |

### Tools to check your own environment

| File | Contents |
|---|---|
| [`os-patch-check-notes.md`](os-patch-check-notes.md) (JA + EN summary) | Checks OS updates on a managed machine and writes SARIF for `vuln_triage`, in two scripts: `scripts/os_patch_check_linux.py` (RHEL pending advisories) and `scripts/os_patch_check_windows.py` (HotFixes; pending updates with `--windows-pending`). Check-only. Not yet run on real hosts. |
| [`java-cacerts-emudhra-check-notes.md`](java-cacerts-emudhra-check-notes.md) (JA) | `scripts/java_cacerts_emudhra_check.py`: checks a local JDK's cacerts trust store for CA roots tied to the eMudhra compromise (R14) and cross-checks `java -version` against IPA's published vulnerable-version list for CVE-2026-91403. Check-only; run and verified against this sandbox's own real JDK (caught and fixed a real bug along the way — `java -version`'s error text landed on stdout, not stderr, in this environment). Not yet run against a JDK that actually trusts the affected roots. |
| [`patch-suggest-notes.md`](patch-suggest-notes.md) (JA + EN summary) | `scripts/patch_suggest.py`: turns findings into proposed diffs (never auto-applies; per-file y/N confirmation). Secret values are never sent to the LLM. |
| [`zgrab2-notes.md`](zgrab2-notes.md) (JA + EN summary) | Ingesting zgrab2 (ZMap's application-layer scanner) output into `vuln_triage`, plus `scripts/zgrab2_guard.py`, an allowlist guard in front of zgrab2. Exposure inventory, not a vulnerability scanner. |
| [`dep-cve-check-notes.md`](dep-cve-check-notes.md) (JA + EN summary) | `scripts/dep_cve_check.py`: checks `requirements.txt` (pip, `==`-pinned lines) and npm's `package-lock.json` against the public OSV.dev vulnerability database. Outputs SARIF, loadable directly into `vuln_triage`. Verified with a mock server; the real OSV API has not been verified. |
| [`ghsa-lookup-notes.md`](ghsa-lookup-notes.md) (JA + EN summary) | `scripts/ghsa_lookup.py`: fetches a GitHub Security Advisory's structured data (affected/fixed versions, CWE, CVSS) by GHSA ID or CVE number from the public Advisories API, and transcribes it to Markdown **verbatim, with no summarization** — to prevent the kind of mix-up-two-CVEs error made earlier in this repo. Verified with a mock server; the real API could not be reached from this session due to this session's own GitHub-integration scoping. |

### CVP (Cyber Verification Program) readiness

| File | Contents |
|---|---|
| [`cvp-application-form-draft.md`](cvp-application-form-draft.md) (EN answers + JA notes) | Draft answers for the CVP application form (Defense Access): pre-submission checklist, per-field answers, and what not to claim. **Fields only you can fill (e.g. vulnerability track record) are left blank.** |
| [`cvp-readiness.md`](cvp-readiness.md) (JA) / [`.en.md`](cvp-readiness.en.md) (EN) | Anthropic Cyber Verification Program tier mapping and application readiness. |
| [`cvp-package/`](cvp-package/) | Application package (HTML / PDF), including the dashboard PDF. Rebuild the HTML/PDF from the source docs with `python3 security-scan/cvp-package/build_package.py` (needs pandoc and Chromium). |

### Other

| File | Contents |
|---|---|
| [`sandbox-defense-model.ja.md`](sandbox-defense-model.ja.md) (JA) / [`.en.md`](sandbox-defense-model.en.md) (EN) | Sandbox defense model by scan pattern + what "ephemeral" really means. Defensive, no real scanning. |

## Detection quick reference (by priority)

**The Gambit lineage (offensive AI agents, R1–R8)**

1. **R1 / R4** — LLM / messaging API egress from server-zone hosts (top priority)
2. **R2** — privileged / host-net / unknown-image container start
3. **R7** — one parent process running many security tools in a short window
   (**the behavioral core that survives even a local-LLM setup**)
4. **R3** — recon-style web enumeration burst
5. **R5** — new persistence (cron / systemd)
6. **R6** — correlation that ties the chain together

**LLM-target-attacks (R9–R11, patterns C/D/E in `llm-target-attacks.en.md`)**

- **R9** — LLM/agent egress steered to a non-allowlisted domain (a sign of IDPI)
- **R10** — an AI workload accessing the cloud metadata service's credential endpoint
- **R11** — a tool call inside a multi-agent session with no direct user instruction (requires app instrumentation)

## Languages

- Narrative notes and runbooks are authored in Japanese; English mirrors are provided
  for the main outward-facing docs (`*.en.md`) and this README.
- `detections/` rules keep **English descriptions** for SIEM portability; their meaning
  is explained in `detections/README.md` and the notes.
