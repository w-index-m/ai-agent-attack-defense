# Defense Playbook for AI-Agent Attacks

日本語: [`defense-playbook.ja.md`](defense-playbook.ja.md)

Knowing how the offensive AI agents (Strix / Cairn / Hermes / ARTEX) behave, this playbook turns "how do we protect our own environment"
into concrete prevention, detection, response and verification — step by step along the attack chain.

> **Assumptions and limits (read first)**
> - What we know about the opponent's tools comes from **public information and static review of public source** ([`artex-analysis.en.md`](artex-analysis.en.md),
>   [`defense-detection-notes.en.md`](defense-detection-notes.en.md), etc.). Attackers may not use these tools, and may not follow this order.
> - **No attack procedures, weaponization or safety-bypass techniques.** The trap design (§5) is a design memo; **active counter-measures against attackers are out of scope**.
> - Applies only to **environments you own or are authorized to test**, including checks and exercises.
> - Where this repo **does not yet have** a control, it is marked **not implemented** (§9). We avoid wording that reads as if it exists.

---

## 0. How to use this

- **Audit**: turn the "Prevent" items in §3 into a checklist for your environment.
- **Implement detection**: follow the "Detect" items in §3 to the rules in [`detections/`](detections/). What has no rule is listed in §9.
- **Incident response**: §4. **Exercises**: §7.
- **What to do in the first week**: §8.

---

## 1. Know the opponent: what the four tools look like

| Tool | Type | Traits (from our analysis) | Main countermeasures |
|---|---|---|---|
| **Strix** | Recon / vulnerability discovery | Runs in a Docker sandbox; captures HTTP through a proxy; bundles nmap / ffuf / browser automation | Reduce exposure, WAF and rate limits, isolate admin UIs (R3) |
| **Cairn** | Exploratory intrusion | A blackboard server (:8000) with a fact/intent graph; launches many worker containers (NET_RAW / NET_ADMIN); keeps trying with other intents after failures | Container monitoring (R2), internal segmentation, egress limits |
| **Hermes** | Orchestration / post-actions | Extended by skills; connects to messaging apps (Telegram etc.); cron; spawns many sub-agents | Outbound messaging (R4), persistence (R5), governance (G1–G6) |
| **ARTEX** | Planner + workers with shared graphs | A single planner generates intents; a recording proxy; MCP; a skills directory; built-in approval gates and destructive-operation deny rules | Egress (R1, R4), recon (R3), rapid multi-tool execution (R7) |

**Common traits**: an LLM is called as the "brain" (outbound HTTPS if cloud-hosted), many kinds of tools run in quick succession, and recon enumerates broadly.

### Where and how it shows up (do not mix these up)
| Pattern | Situation | What you can see |
|---|---|---|
| **1. Receiving-side traces** | Recon and web attacks coming from outside | Bursts of requests, spikes of 404 / 403 / 5xx, external access to admin URLs (**R3**, app logs) |
| **2. Activity on a foothold** | After a break-in, tools or agents run on your server | LLM API traffic (**R1**), privileged containers (**R2**), messaging (**R4**), persistence (**R5**), rapid multi-tool execution (**R7**) |
| **3. Your own agents** | You run offensive agents internally | Approvals, scope, records (**G1–G6**). R1 and R7 can also reveal use in unexpected places |

- **LLM traffic that leaves the attacker's own infrastructure is invisible to you.** While you are only being attacked from outside, what you see is pattern 1. R1, R2, R4, R5 and R7 matter after a foothold exists (2) or inside your own environment (3).
- **If the attacker uses a local LLM, R1 never fires.** Shift the weight to R7, R2 and the receiving-side traces.

---

## 2. Five principles

1. **Reduce what can be found.** Agents enumerate fast. Remove exposure and known weaknesses first (netcheck, `vuln_triage`, patching).
2. **Break the chain in the middle.** The attack only works if every step succeeds. Put a different control at each step.
3. **Detect machine speed.** Superhuman bursts of execution and enumeration (R7, R3) remain even with a local LLM.
4. **Narrow the exits.** Even with a foothold, an allowlist on outbound traffic (LLM, C2) makes it harder to operate (R1, R4).
5. **Govern your own agents too.** Give them approvals, privileges and records (G1–G6).

---

## 3. The seven-step chain × defense

The chain from the Gambit case (definition: [`../shared/taxonomy.json`](../shared/taxonomy.json)). Each step lists Prevent → Detect → Respond → Verify.
**[Not implemented]** in a Detect line means this repo has no rule for it (§9).

### ① SQL injection on the login page
- **Prevent**: use placeholders (parameterized queries); never embed variables in raw queries, even with an ORM; give the DB account only the operations it needs on the tables it needs. WAF and rate limits are supplementary.
- **Detect**: bursts of requests from one source and error spikes (**R3**: [Sigma](detections/sigma/r3_recon_enumeration_burst.yml) / [Elastic](detections/elastic/r3_recon_burst.json) / [Datadog](detections/datadog/r3_recon_burst.json)); DB errors in app logs.
- **Respond**: temporarily disable the endpoint, preserve logs, block the source (weak against distributed IPs).
- **Verify**: search for string-concatenated SQL with Semgrep in CI; re-test the same input in a staging environment.

### ② OTPs stored in plaintext in the DB (MFA bypass)
- **Prevent**: store OTPs hashed and expire them in about five minutes; cap attempts and lock after the cap; store passwords with slow hashes (bcrypt / argon2).
- **Detect**: many attempts on one account in a short time, authentication anomalies. **[Not implemented]** (no rule for authentication logs)
- **Respond**: invalidate and reissue the affected accounts' OTPs and sessions.
- **Verify**: inspect DB tables for authentication values left in plaintext.

### ③ No extension check on the admin upload (web shell placement)
- **Prevent**: decide allowed extensions with an allowlist and also validate content; store outside the web root with no execute permission; regenerate file names; put the admin UI behind VPN / IP restriction with MFA; make the web root read-only (files 644, directories 755; exclude paths that need writes).
- **Detect**: new files in the web root or upload directory, and child processes spawned under the web server. **[Not implemented]** (R5 covers cron / systemd persistence, not web-shell placement itself; for external FIM see [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md)). External access to admin URLs can be checked with **R3** and netcheck.
- **Respond**: copy the file **before** deleting it to preserve evidence, then quarantine it; review the account that was the path; rotate credentials.
- **Verify**: in your staging environment, upload a non-image file from the admin UI and confirm it is rejected; use netcheck to see which admin-like URLs are exposed.

### ④ sudo without a password (privilege escalation)
- **Prevent**: remove NOPASSWD and allow only specific commands; do not give the web app's user sudo; run containers as a non-root user and drop privileged mode and unneeded capabilities.
- **Detect**: starts of privileged or NET_RAW containers (**R2**: [Sigma](detections/sigma/r2_privileged_container_spawn.yml) / [Falco](detections/falco/cairn-ai-agent.yaml) / [Elastic](detections/elastic/r2_privileged_container.json)). Abnormal sudo use is **[not implemented]**.
- **Respond**: isolate the host; revoke accounts and keys; rebuild from the image.
- **Verify**: run `sudo -l` as the service user to see its scope.

### ⑤ NFS misconfiguration and credentials in config files
- **Prevent**: remove `no_root_squash` (use `root_squash`) and restrict clients (read-only where enough); keep credentials out of config files and pass them through environment variables or a secrets service; run gitleaks in pre-commit and CI.
- **Detect**: unusual reads of credential files, use of decoy credentials (§5). **[Not implemented]**
- **Respond**: **invalidate leaked credentials immediately and reissue them.** Remove them from Git history too (deleting alone leaves them in history).
- **Verify**: review `/etc/exports`; run gitleaks across history.

### ⑥ Bulk retrieval from Secrets Manager (over-broad IAM)
- **Prevent**: stop using `*` in allowances; allow each app only the one secret it needs; avoid long-lived access keys.
- **Detect**: in cloud audit logs, many secrets read in a short time, or access from an unusual principal or place. **[Not implemented]**
- **Respond**: revoke the principal's permissions and disable the keys; reissue every secret that may have leaked (priority order in §4.2).
- **Verify**: use tools such as IAM Access Analyzer to list unused permissions and anything exposed externally.
- Equivalents on other clouds: see the appendix of [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md).

### ⑦ The card-data encryption key is reachable from the same environment
- **Prevent**: do not hold card numbers yourself — use the payment provider's tokenization; keep keys in a separate mechanism such as KMS and give the app only decrypt permission; use hosted payment fields and use CSP and SRI to block script injection; do not use MD5 / SHA-1 / ECB.
- **Detect**: abnormal key access (a spike in KMS Decrypt calls, an unusual principal). **[Not implemented]** Tampering with payment-page scripts can be noticed via CSP Report-Only reports; DOM monitoring is supplementary.
- **Respond**: rotate the key; confirm whether the card brand and payment provider must be contacted; temporarily stop the payment page.
- **Verify**: list where the keys are and who can access them, and confirm they are not in the same environment as the data; use netcheck to see whether the payment page has a CSP.

---

## 4. From detection to response

### 4.1 First move by signal
| Signal | Check first | Containment |
|---|---|---|
| **R1 / R4** (LLM / messaging traffic) | The business purpose of the source host | If not legitimate, cut egress and investigate processes and containers |
| **R2** (privileged container) | Who started it, image origin, need for the capabilities | Unknown image + privileged is high-confidence; isolate and stop |
| **R3** (enumeration burst) | Exposure of the targeted asset (netcheck) | Close the exposure; block if it continues |
| **R5** (persistence) | The process lineage that created it | Remove the persistence and trace the lineage |
| **R7** (rapid multi-tool execution) | The parent process and the list of tools executed | Correlate with R1 and R2; if alone, confirm whether it is legitimate use |
| **R6** (correlation) | Treat it as a chain beyond isolated signals | Declare an incident and go to §4.2 |
| **G1–G6** (governance) | The agent and session concerned | Preserve the session and deny at the outer safety layer |

### 4.2 Incident flow
1. **Initial response**: assign owners and start a log. Preserve logs, process lists and network connections. Form a hypothesis of **how far the chain got** (① to ⑦).
2. **Containment**: isolate the suspect host from the network (do not power it off right away; preservation first). Cut egress and suspend suspicious accounts.
3. **Eradication**: remove persistence (cron, systemd, startup items) and web shells. **Rebuilding from the image** is the reliable way.
4. **Credential rotation** (scope by how far the chain got; priority order):
   1. Long-lived cloud keys and administrator credentials
   2. DB and application secrets
   3. Everything in Secrets Manager (if it got as far as ⑥)
   4. Payment keys (if it got as far as ⑦)
5. **Recovery**: restore from an immutable backup whose restore you have tested; patch; confirm it does not recur.
6. **Notification**: when personal or card data is involved, have the responsible people or specialists confirm legal and contractual notification duties (which can have deadlines).
7. **Retrospective**: record at which step you detected it or failed to, and update the rules and checklists (procedure: [`../shared/README.md`](../shared/README.md)).

### 4.3 Automate in stages
Go **alert only → blocking with human approval → limited automatic blocking**. Jumping straight to auto-blocking lets false positives take down your own service.
Automatic IP blocking is weak against distributed IPs and slow attacks; combine it with allowlists and rate limits.

---

## 5. Decoy-based detection (honeytokens) — design memo [not implemented]

**Idea**: place fake credentials and fake data that no real business process uses, where an automated enumerator is likely to pick them up. **Any use is almost certainly malicious**, so the alert has few false positives.

| Example placement (step) | Content | Alert condition |
|---|---|---|
| Config files, example files in repos (⑤) | A fake key for a non-existent service | An attempted authentication with that key |
| Secrets Manager (⑥) | A secret with a decoy name | A read of that secret |
| DB (①②) | A fake table or fake account | A read, or a login attempt with that account |
| A fake administrator account (③④) | A non-existent user | A login attempt |

**Design cautions**:
- **Never use real credentials or real data.** Make sure a decoy can reach nothing.
- Give each decoy a **unique identifier** so you can tell where it leaked from.
- Keep a **register** so staff do not trip them by accident; actually test the alert path.
- Do not disturb production data quality or operations; check privacy and contractual aspects.
- **Limit**: if the attacker never touches them, nothing fires. **This is a detection aid, not prevention.**

**Out of scope here**: active counter-measures such as injecting instructions into the attacker's agent to disrupt it, or hitting back at the attacker's environment. They carry legal risk and are not reliable.

---

## 6. When you run agents yourself (G1–G6)

If your organization runs offensive agents (for red-teaming, etc.) **under authorization**, require the following. ARTEX's built-in mechanisms are a good template.

- **Approval gate**: rule tool calls as allow / deny / confirm; deny destructive operations (delete-style APIs) by default.
- **Scope enforcement**: make it impossible to go outside the authorized targets.
- **Records**: keep LLM calls and tool executions.
- **G1**: govern skill installation, auto-generation and self-modification by provenance, signature and review.
- **G2, G3**: deny and record changes to safety settings and any intent to bypass safeguards, at an outer safety layer.
- **G4**: detect missing or stopped logs (suspect an attack on the logging itself).
- **G5, G6**: require human approval for privilege expansion, and watch the number and privileges of sub-agents.

---

## 7. Verification and exercises (within authorized scope)

- **Exposure checks**: run netcheck on your own assets. If you use zgrab2, narrow the targets with [`../scripts/zgrab2_guard.py`](../scripts/zgrab2_guard.py). Prioritize the results in `vuln_triage.html`.
- **Checking detection rules**: in a staging environment, create **harmless simulated activity** and see whether alerts fire.
  For example: R3 — many requests for non-existent paths against your own test server; R7 — run harmless version-printing commands for many different tools in succession; R2 — start a privileged container in staging.
- **Tabletop**: walk through the seven steps of §3 one at a time, saying out loud "can we notice here?" and "who does what?".
- **Metrics**: time to detect, time to contain, and the number of the seven steps that have both prevention and detection (§9).
- **Running real offensive tools happens only in an authorized, isolated lab** (procedure: [`cairn-lab/cairn-authorized-lab-runbook.md`](cairn-lab/cairn-authorized-lab-runbook.md)).

---

## 8. What to do in the first week (priority order)

1. **Check exposure**: run netcheck on your assets. Are management planes (vCenter, ESXi, admin UIs) reachable from outside?
2. **Inventory secrets**: run gitleaks across history. Invalidate and reissue whatever it finds.
3. **Narrow outbound traffic**: block LLM API and messaging traffic from server-zone hosts by default (the precondition for R1 and R4).
4. **Tighten IAM**: find `*` allowances and narrow them (⑥).
5. **Deploy detection**: bring in R1, R4 and R2 first, starting with alert only.
6. **Verify recovery**: **actually restore** from an immutable backup.

---

## 9. Current map: what this repo can do, and what is not implemented

| Step | Prevention check (this repo) | Detection (this repo) | Not implemented / needed elsewhere |
|---|---|---|---|
| ① SQLi | Semgrep (CI) | R3 | WAF (operations side) |
| ② OTP | Manual check | **None** | Authentication-log anomaly detection |
| ③ Upload | netcheck (admin exposure), Semgrep | R3 (external access) | Web-root file monitoring (FIM), child-process monitoring |
| ④ sudo | Trivy (config findings) | R2 (privileged containers) | Abnormal-sudo detection (auditd or an EDR) |
| ⑤ NFS / credentials | gitleaks, Trivy | **None** | File-access auditing, decoys (§5) |
| ⑥ IAM | Trivy (IaC findings) | **None** | Cloud audit-log detection |
| ⑦ Keys / card data | netcheck (CSP present?) | **None** | KMS auditing, collecting CSP Report-Only reports |

- **R1–R7 are mainly network and host observations.** Detection for ②⑤⑥⑦ lives in the app and cloud audit-log layer, and **does not exist yet**. That is the next task.
- **Response (§4) is documentation only**; there is no automation.
- **Decoys (§5) are a design only**, with no rules or implementation.
- **We have not verified, on real offensive tools, that detection works** (that needs an authorized lab).

---

## 10. Related files

- Detection rules: [`detections/`](detections/) (R1–R7; Sigma / Falco / Elastic / Datadog)
- Detection concepts and terms: [`defense-detection-notes.en.md`](defense-detection-notes.en.md), [`glossary.ja.md`](glossary.ja.md)
- The four layers and the external roadmap assessment: [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md)
- Per-tool analyses: [`artex-analysis.en.md`](artex-analysis.en.md), [`strix-local-backend-notes.md`](strix-local-backend-notes.md), [`cairn-lab/cairn-authorized-lab-runbook.md`](cairn-lab/cairn-authorized-lab-runbook.md)
- Audit tools: [`../netcheck/`](../netcheck/), [`../vuln_triage.html`](../vuln_triage.html), [`zgrab2-notes.md`](zgrab2-notes.md)

> Defense, detection and recovery design only. No attack procedures or safety-bypass techniques.
