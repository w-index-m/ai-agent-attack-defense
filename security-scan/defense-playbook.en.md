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
- **Detect**: new files in the web root or upload directory, and child processes spawned under the web server. **R8** ([Sigma](detections/sigma/r8_webshell_placement_and_spawn.yml) and Falco; two rules: placement, and a shell spawned by a web server. Elastic / Datadog versions are not implemented, and nothing has been validated in a real environment). R5 covers cron / systemd persistence, not web-shell placement itself; for external FIM see [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md). External access to admin URLs can be checked with **R3** and netcheck.
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

### 3A. Patterns from the Japanese advisories (APIs, BI tools, admin misconfiguration)
The October 2026 advisories from JPCERT/CC and the Personal Information Protection Commission describe, beyond the seven steps above, **API abuse, exploitation of known vulnerabilities (including BI tools), device/admin misconfiguration, and web-shell placement**. The mapping is in [`jp-advisory-mapping.en.md`](jp-advisory-mapping.en.md). This section only adds defensive items (no attack procedures).

**A. API authorization (never touch another user's data)**
- **Prevent**: on every request, check on the server whether *this user* may access *this data*; being logged in is not enough. Even if IDs or parameters are altered, other users' data must not be returned. Put operations that the UI never exposes (role changes, account creation) behind an admin path with admin authentication and source restrictions. Accept only permitted users and HTTP methods on each endpoint. Set an upper limit on requests per unit time, and give high-load or high-abuse functions (login, password reset, SMS sending, search) their own rate and usage limits (a JPCERT/CC recommendation).
- **Detect**: a burst of API calls from one principal; a spike in 401/403; runs of errors from malformed authentication tokens; calls to internal APIs that are normally unused. **[Not implemented]** (no API-log rules exist; R3 covers web enumeration).
- **Respond**: pause or throttle the API; identify affected users and confirm whether notification is required; preserve logs.
- **Verify**: in your own test environment, confirm per API that user A's session cannot retrieve user B's data.

**B. API keys and secrets inside apps**
- **Prevent**: do not embed high-privilege keys in public apps (such as mobile apps). Scope keys by purpose and permission and rotate them regularly. Do not reuse keys leaked from other systems. Give API users and tokens only the minimum necessary permissions, give tokens a suitable expiry and avoid long-lived ones, and be able to revoke quickly any that are no longer needed or suspected leaked.
- **Detect**: key use from unusual locations or times. **[Not implemented]** (use of decoy keys is a design memo in §5).
- **Respond**: immediately revoke and reissue any key that may have leaked.
- **Verify**: run gitleaks over the repository and its history for leftover keys.

**C. Exposure and patching of BI tools and employee-facing systems**
- **Prevent**: keep BI tools, admin screens, and internal systems from being directly visible from the internet (place them behind a VPN or IP restrictions). Subscribe to product vulnerability notices and prioritize patching (for example, the Metabase SQL injection CVE-2026-72898; see JPCERT-AT-2026-0023).
- **Detect**: external access to admin ports or admin screens (**R3** and netcheck). Detection of per-product exploitation is **[not implemented]**.
- **Respond**: stop the exposure, apply the patch, check for signs of compromise (preserve first).
- **Verify**: use netcheck for admin exposure; use the OS update checks (`os_patch_check_*`) and Trivy for missed patches. `os_patch_check_*` covers the OS only, not apps such as Metabase, so check app patching separately.
- **If you run Metabase** (**two separate** SQL injection vulnerabilities were published on 2026-08-06. Sources: the original of JPCERT/CC's JPCERT-AT-2026-0023, and a summary of Metabase advisory GHSA-r8h2-qpfx-mx59):
  - **CVE-2026-72898** (GHSA-vwf4-m7j8-wcjf; admin access through an unauthenticated endpoint; zero-day attacks confirmed, per Metabase): upgrade to the latest version. Until you can, **block access to `/api/session/reset_password`** at network devices. If that path was reachable from the internet, **do not stop at upgrading; check for compromise**. A log sequence of `POST /api/session/reset_password` (HTTP 400) followed by `GET /api/user/current` (HTTP 200) indicates a likely compromise.
  - **CVE-2026-72899** (GHSA-r8h2-qpfx-mx59; an unauthenticated attacker can run SQL through a publicly shared card or dashboard that exposes a field-filter (dimension) parameter and gain admin access; the public link's UUID is enough, and **public sharing is enabled by default**; Critical; **confirmed against the original of Metabase's advisory**; the CVSS 9.6 figure is from a summary): the interim measure is to **disable public sharing, or unpublish public links that expose field-filter parameters**. If such links existed, then after upgrading: revoke sessions by deleting every row of `core_session` (`TRUNCATE TABLE core_session`); review API keys and administrator accounts; rotate the credentials of connected databases; and review logs. The original does not state that exploitation was confirmed. JPCERT/CC notes that information that appears to be a PoC has been published.
  - **Fixed versions**: 58.24 / 59.21 / 60.17 / 61.11 / 62.9 / 63.5 (in the form `x.58.24`). For both 72898 and 72899 the versions are confirmed against the originals (JPCERT/CC and Metabase's advisories); the affected versions are those before x.58.24, x.59.21, x.60.17, x.61.11, x.62.9, and x.63.5, respectively. Versions before the 58 line are not affected by 72898. Metabase Cloud had already been mitigated for 72898.
  - **Confirmed against the original of Metabase's advisory (GHSA-vwf4-m7j8-wcjf)**: CVE-2026-72898 is Critical (the CVSS 10.0 figure is from a summary), and the vendor states that **active exploitation was confirmed**. If `/api/session/reset_password` was publicly reachable, then after upgrading it advises: revoke all sessions by deleting every row of the application database's `core_session` table; review API keys and administrator accounts; rotate the credentials of connected databases; and review data-warehouse logs and Metabase's activity and query history.
  - **If you suspect compromise**: check user sessions, API keys, and admin accounts; rotate the credentials of connected databases; review the logs of Metabase and the connected databases.

**D. Configuration files and backups**
- **Prevent**: do not keep configuration files, environment files, backups, or logs in locations reachable over the web. Delete files you no longer need.
- **Detect**: access to configuration or backup files under the web root. **[Not implemented]**
- **Respond**: remove the files and reissue any credentials they contained.
- **Verify**: inventory the web root. **netcheck checks for this kind of file exposure** (15 items such as `.env`, `.git`, DB dumps, and backups; it reports only when the response signature matches and never stores or shows the content; not yet run on real hosts).

**E. Common preparations (summary of JPCERT/CC's recommendations)**
- **Prevent**: restrict access by region if the service's users are regionally limited. Stop exposing services or functions (such as admin features) not needed for the business. Do not keep data past its retention period or purpose.
- **Detect / first response**: review the intrusion-detection setup and the first-response procedure (§4).
- **After a compromise**: review lateral-movement countermeasures for after a web server or similar is compromised (steps ④⑤⑥ in §3).
- **Customers**: prepare, in peacetime, the messaging to prevent secondary harm if a leak occurs (for example, urging multi-factor authentication).
- **Scope**: apply the same review to systems not meant for an unspecified public, such as employee-facing systems and BI tools.

### 3B. Where to place a WAF (network-architecture choices)
This expands on "a WAF is supplementary" from step ①. **A WAF is not a substitute for fixing the code** (see §3 ①). Whatever the setup, start with alerting only and confirm false positives before moving to blocking (§4.3).

- **Cloud WAF** (Cloudflare, AWS WAF, and similar): configured through the vendor's console; this repository builds no tool for it. Make sure the origin (your own server) is not reachable by a direct path that bypasses the WAF — a direct path lets attackers route around it.
- **Running a WAF on your own load balancer** (for example F5 BIG-IP's LTM plus ASM/Advanced WAF): the WAF module sits on a device that already terminates TLS. Because **nothing has to be decrypted a second time**, this tends to add less latency and keep the setup simpler. Points to watch:
  - ASM/Advanced WAF is licensed separately from LTM.
  - Any path that reaches the server without passing through BIG-IP is unprotected; pair this with reducing exposure (§3A-C, §3A-D).
  - The violation log records the matched signature and the actual request path and parameters. **This is useful for the log-pattern checks in a compromise investigation (§5)**, so forward it to your SIEM.
- **Decrypting and inspecting at an NGFW** (for example Palo Alto's Threat Prevention / Vulnerability Protection):
  - **While traffic stays encrypted, the HTTP path and query contents are not visible.** App-ID only makes a heuristic guess at the kind of traffic (web, MySQL, and so on); it does not look at the content (such as a SQL injection string).
  - Inspecting the content requires decryption via **SSL Inbound Inspection**: import the protected server's private key into the firewall, which then decrypts, inspects, and re-encrypts the relevant traffic.
  - This comes with private-key management and added processing load. Decide, against legal and internal policy, whether to exclude traffic carrying personal or payment data from decryption.
  - If a device such as BIG-IP already terminates TLS, inspecting there is simpler, since decryption only happens once.
- **Rule of thumb**: if a device that already terminates TLS (a load balancer or reverse proxy) exists, put the WAF there. Otherwise, a cloud WAF is the easy option. Treat NGFW decryption as covering a separate role — defending non-web protocols such as direct database connections.

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
| ③ Upload | netcheck (admin exposure), Semgrep | R3 (external access), R8 (placement / shell spawn; Sigma and Falco) | R8 for Elastic / Datadog, tuning and validation in a real environment |
| ④ sudo | Trivy (config findings) | R2 (privileged containers) | Abnormal-sudo detection (auditd or an EDR) |
| ⑤ NFS / credentials | gitleaks, Trivy | **None** | File-access auditing, decoys (§5) |
| ⑥ IAM | Trivy (IaC findings) | **None** | Cloud audit-log detection |
| ⑦ Keys / card data | netcheck (CSP present?) | **None** | KMS auditing, collecting CSP Report-Only reports |
| 3A-A API authorization | **None** (manual check) | **None** | API-log anomaly detection |
| 3A-B API keys | gitleaks | **None** | Key-use anomaly detection, decoys (§5) |
| 3A-C BI / admin systems | netcheck, OS update checks, Trivy | R3 (external access) | Per-product exploitation detection |
| 3A-D Config / backups | netcheck (15-item exposure check) | **None** | Web-root inventory, detection of file access |

- **R1–R8 are mainly network and host observations.** Detection for ②⑤⑥⑦ lives in the app and cloud audit-log layer, and **does not exist yet**. That is the next task.
- **Response (§4) is documentation only**; there is no automation.
- **Decoys (§5) are a design only**, with no rules or implementation.
- **We have not verified, on real offensive tools, that detection works** (that needs an authorized lab).

---

## 10. Related files

- Detection rules: [`detections/`](detections/) (R1–R8; Sigma / Falco / Elastic / Datadog)
- Detection concepts and terms: [`defense-detection-notes.en.md`](defense-detection-notes.en.md), [`glossary.ja.md`](glossary.ja.md)
- The four layers and the external roadmap assessment: [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md)
- Per-tool analyses: [`artex-analysis.en.md`](artex-analysis.en.md), [`strix-local-backend-notes.md`](strix-local-backend-notes.md), [`cairn-lab/cairn-authorized-lab-runbook.md`](cairn-lab/cairn-authorized-lab-runbook.md)
- Mapping to the Japanese advisories: [`jp-advisory-mapping.en.md`](jp-advisory-mapping.en.md)
- Audit tools: [`../netcheck/`](../netcheck/), [`../vuln_triage.html`](../vuln_triage.html), [`zgrab2-notes.md`](zgrab2-notes.md)

> Defense, detection and recovery design only. No attack procedures or safety-bypass techniques.
