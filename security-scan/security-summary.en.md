# Security summary (English)

日本語: [`security-summary.ja.md`](security-summary.ja.md)

One page on the AI-agent attacks and known vulnerabilities covered in this repository: **what happened, what we built, and what is not yet verified.**
See the linked documents for details.

> ⚠️ Scope: this repository is limited to **detection, defense, and verification**. It contains no attack procedures, weaponization,
> or safety-bypass techniques. The attack tools are subjects of analysis, not used against any target. Run anything only against systems you own or have written authorization to test.

---

## 1. The attacker side (what was studied)

### 1-1. Gambit Security report (2026-09-22)
An attack on online retailers in which three AI tools were used in a division of labor.

| Tool | Role |
|---|---|
| Strix | Reconnaissance and vulnerability discovery |
| Cairn | Exploratory intrusion (runs autonomously toward a goal) |
| Hermes | Orchestration and post-actions (extensible through skills) |

The attack chain has seven steps. Each has a corresponding defense (see [`defense-playbook.en.md`](defense-playbook.en.md), §3).

| Step | Attack | Main defenses |
|---|---|---|
| ① | SQL injection on the login page | Parameterized queries, least-privilege DB accounts |
| ② | OTPs stored in plaintext (MFA bypass) | Hashing, short expiry, attempt limits |
| ③ | Admin upload with no extension check (web shell) | Allowlists, non-executable storage, read-only web root |
| ④ | sudo without a password (privilege escalation) | Remove NOPASSWD, allow only specific commands |
| ⑤ | NFS misconfiguration and credentials in config files | Remove no_root_squash, keep secrets out of config |
| ⑥ | Bulk retrieval from Secrets Manager (over-broad IAM) | Least privilege, one secret per app |
| ⑦ | Card-data encryption key reachable from the same environment | Tokenization, key separation (KMS) |

### 1-2. ARTEX (an autonomous AI penetration-testing agent)
An open-source tool reported to have won Baidu's offense/defense challenge. It has a planner and workers, a recording proxy,
and an approval gate. See [`artex-analysis.en.md`](artex-analysis.en.md).

- **The link to a Korean financial-institution breach** is from press reports only and is **unconfirmed**.
- The claim of a zero-day found with no human intervention is a secondhand report from a Chinese community and is **unverified**.

---

## 2. Known vulnerabilities (separate)

### 2-1. VMware VMSA-2026-0006
Includes an unauthenticated remote code execution in vCenter (maximum CVSS 9.8). **No workaround exists; patching is the only remedy.**
Known critical vulnerabilities like this are targeted by automated tools whether or not AI agents are involved.
This repository covers it through management-plane exposure checks (ports 902 / 5480 / 9443 in netcheck) and §5.1 of
[`defense-detection-notes.en.md`](defense-detection-notes.en.md).

---

## 3. What a company should do

| Action | Content | Support in this repository |
|---|---|---|
| **Fix SQL injection** | Convert the affected code to parameterized queries and search the codebase for the same pattern | Semgrep (CI), `patch_suggest.py` (proposed diffs) |
| **DB privileges** | Give the application's account only the operations it needs | Manual (playbook §3 ①) |
| **Protect secrets** | Hash passwords and OTPs; separate keys into KMS or similar | gitleaks (CI), playbook §3 ②⑦ |
| **Reduce exposure** | Do not expose admin UIs, databases, or local LLM APIs directly to the internet | `netcheck`, `zgrab2_guard.py` |
| **Restrict outbound traffic** | Allowlist server-side traffic to LLM and messaging endpoints | Detections R1 and R4 |
| **Patch** | Prioritize known critical vulnerabilities in the OS (RHEL, Windows) and products (e.g. vCenter) | `os_patch_check_linux.py`, `os_patch_check_windows.py` |
| **Detect** | Load the R1–R7 rules into your log platform (SIEM) | `detections/` (Sigma, Falco, Elastic, Datadog) |

---

## 4. What this repository provides

| Kind | Content | Document |
|---|---|---|
| Audit | netcheck (exposure), Semgrep / Trivy / gitleaks (CI), zgrab2 ingestion and guard | [`zgrab2-notes.md`](zgrab2-notes.md) |
| Triage | `vuln_triage.html` (prioritization, with a local-LLM question panel) | [`../README.md`](../README.md) |
| Fix assistance | `patch_suggest.py` (produces diffs; each is applied only after a human confirms) | [`patch-suggest-notes.md`](patch-suggest-notes.md) |
| OS update checks | Two scripts, Linux (RHEL) and Windows (check-only, SARIF output) | [`os-patch-check-notes.md`](os-patch-check-notes.md) |
| Detection | R1–R7 rules (Sigma, Falco, Elastic, Datadog) | [`detections/README.md`](detections/README.md) |
| Defense docs | Defense playbook, the four-layer overview, glossary | [`defense-playbook.en.md`](defense-playbook.en.md), [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md), [`glossary.ja.md`](glossary.ja.md) |
| Analysis | Strix and Cairn local verification, ARTEX static analysis, defense notes | [`defense-detection-notes.en.md`](defense-detection-notes.en.md) |

---

## 5. Verification status (honestly)

| Item | Status |
|---|---|
| Tool syntax and the consistency check (CI) | ✅ Verified |
| netcheck and zgrab2 ingestion | ✅ Verified with sample data and mocks |
| `patch_suggest.py` | ✅ Generate → review → apply verified in a temporary repo with a mock LLM |
| OS update checks (RHEL, Windows) | ⚠️ Verified only with stubs that mimic the output. **Not yet run on real hosts** |
| Local-LLM question panel | ⚠️ Verified only with a mock server. **Not yet verified with a real Ollama (qwen2.5:1.5b)** |
| Effectiveness of the detection rules | ⚠️ Not validated against a real attack environment (needs an authorized lab) |
| Attack tools (Strix, Cairn, Hermes, ARTEX) | ✅ Analysis only. No attacks run against real targets |

---

## 6. Limits and cautions

- **Small local models (qwen2.5:1.5b) can give wrong answers or wrong fixes.** A person must always check them.
- **The research is based on public information.** Attackers may not follow this order. Press reports are treated as unconfirmed.
- **The detection rules are single signals.** Thresholds and allowlists need tuning per environment. Most detection power comes from correlation (R6).
- **Automate in stages.** Automatic blocking can take down your own service through false positives. Start with alerts only.

---

## 7. What to do next (priority order)

1. On your own servers, run netcheck and the OS update checks, and review the results in `vuln_triage.html`
2. Convert any SQL injection you find to parameterized queries
3. After the fix, re-check with Semgrep for the same pattern
4. Confirm that admin UIs and databases are not directly reachable from the internet
5. Check the patch status of known critical vulnerabilities (such as vCenter)

---

> Detection, defense, and verification design only. No attack procedures or safety-bypass techniques.
