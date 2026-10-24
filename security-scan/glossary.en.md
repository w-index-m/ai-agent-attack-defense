# Glossary (plain language)

日本語: [`glossary.ja.md`](glossary.ja.md)

Security terms that come up in this repository and in conversation, explained in **as plain language as possible**. Favors "get the gist quickly" over precision. See each dedicated note for the full detail.

Related: [`defense-detection-notes.md`](defense-detection-notes.md) / [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md)

---

## The defense mindset: 4 layers

Stacking these four is called "defense in depth" — the point is not relying on any single control.

| # | Layer | Plain explanation |
|---|---|---|
| ① | Prevent | Stop the attack from succeeding in the first place: shrink/close the attackable entry points (attack surface). This repo's symbol: **③**. |
| ② | Detect | Notice that an attack happened. This repo's symbols: **R1–R24**. |
| ③ | Respond | Once found, stop it and contain it (block, isolate). |
| ④ | Recover | Be able to restore what was broken (backup, restore). |

### Related terms

Not the 4 layers themselves, but the supporting concepts that come up while putting them into practice.

| Term | Plain explanation | Mainly serves which layer |
|---|---|---|
| Attack surface | How wide the attacker's entry points are. Grows with more open ports, admin panels, outdated components, etc. | ①Prevent |
| Hardening | Not running on defaults: turning off unneeded features, tightening permissions, and so on. | ①Prevent |
| allowlist / denylist | A permit-list vs. a deny-list. An allowlist ("only let through what's explicitly allowed") is the safer default. | ①Prevent |
| Least privilege | Grant only the access actually needed, so a single breach does less damage. | ①Prevent |
| Honeytoken (decoy) | A fake credential or fake piece of data no legitimate business process ever uses. If it's ever used, that's a strong, low-false-positive signal of compromise. A detection aid, not a prevention control. | ②Detect |
| Playbook | A written "in this situation, who does what" procedure. This repo's [`defense-playbook.en.md`](defense-playbook.en.md) covers prevention and response per stage of the attack chain. | ③Respond |
| Rotation (credential/key renewal) | Issuing new keys/credentials and invalidating the old ones. The standard response once something may have leaked. | ③Respond / ④Recover |
| Tabletop exercise | A walkthrough where nothing is actually run — a scenario is talked through step by step to check "would we notice this, and who does what." | Spans ②–④ |

## This repo's symbols

| Symbol | Meaning |
|---|---|
| R1 | Outbound traffic from a server to an external **LLM** (the AI agent calling its "brain") |
| R2 | Launching a **privileged container** (a container with strong capabilities = a dangerous foothold) |
| R3 | A **reconnaissance** enumeration burst (a flurry of probing in a short window) |
| R4 | **C2** traffic over messaging apps (a command channel) |
| R5 | New **persistence** being created (something that survives a reboot) |
| R6 | **Correlation** (bundling R1–R5 and R7 together and detecting the whole "chain") |
| R7 | Many tools run back-to-back in a short window (the core signal that survives even local-LLM-only attackers) |
| R8 | Planting a **web shell** (JSP/WAR/PHP, etc. under the web root) and launching a shell from the web server |
| ③ / ③CSP | **Prevention** (minimizing the attack surface / script control via CSP) |
| G1–G6 | **Governance** audit events (permissions, approvals, log integrity) |

For the full list from R9 onward (LLM-targeted attacks, real individual-CVE responses, etc.), see [`detections/README.md`](detections/README.md). "R" stands for Rule (a detection rule); "G" stands for Governance.

## Attack / intrusion terms

| Term | Plain explanation |
|---|---|
| Recon | Scouting before an attack: looking for open ports, admin panels, and so on. |
| RCE (Remote Code Execution) | A state where an attacker can **run arbitrary programs** on a server over the network. The most dangerous outcome. |
| unauth RCE | RCE that requires **no authentication** — not even a login — so it's especially dangerous. |
| SQLi (SQL injection) | Smuggling malicious SQL through an input field to steal database contents or bypass authentication. |
| XSS | Getting a victim's browser to run an attacker's script on someone else's page. |
| Skimmer (Magecart) | Malicious script planted on a checkout page to **steal card numbers**. |
| Web shell | A "remote-control backdoor program" an attacker plants on a server. |
| Privilege escalation | Going from a regular user's permissions up to administrator (root). Things like passwordless `sudo` are a common hole. |
| Lateral movement | After taking over one machine, spreading to other servers on the internal network. |
| Persistence | Planting something so the attacker keeps a foothold after a reboot (cron, systemd timers, etc.). |
| C2 (Command and Control) | The communication channel an attacker uses to send instructions to compromised machines; chat apps are a common abuse vector. |
| Egress (outbound traffic) | Traffic leaving a server. Restricting this with an allowlist makes C2 and data exfiltration harder. |
| VM escape | Breaking out of a virtual machine to take over the underlying host (hypervisor). |
| Ransomware | An attack that encrypts data and demands a ransom, often also targeting backups so they can't be used to recover. |

## Defensive mechanisms & tools

| Term | Plain explanation |
|---|---|
| CSP (Content Security Policy) | A setting that restricts where a page is allowed to load scripts from. The key control against skimmers. |
| Report-Only | A CSP mode that only logs violations without blocking them — used to safely test a policy before enforcing it in production. |
| SRI (Subresource Integrity) | A mechanism for verifying an external script hasn't been tampered with, via a fingerprint. |
| FIM (File Integrity Monitoring) | Watches important files for changes, new placements, or deletions. "Kernel-level" means catching this in real time via OS-level notifications. Wazuh calls this Syscheck. This repo's symbol: R5. |
| eBPF | A technology for safely running programs inside the Linux kernel, enabling low-overhead behavior monitoring (used by tools like Falco). |
| WORM (Write Once Read Many) | Storage that can't be deleted once written — a ransomware defense. Examples: object-store Object Lock/immutability (AWS S3 Object Lock, Azure immutable blobs, GCP Bucket Lock, WORM NAS, etc.). Windows VSS can be deleted with admin rights, so it isn't "true WORM." |
| MFA / 2FA / OTP | Multi-factor authentication: strengthening identity verification beyond a password, e.g. with a one-time code. Storing OTPs in plaintext defeats much of the point. |
| IAM | Cloud permission management — who can do what. Overly broad IAM means one compromised machine can cascade into much wider damage. |
| NFS / no_root_squash | A file-sharing mechanism and a dangerous setting for it: `no_root_squash` lets a client's root user act as root on the share. |

## Operational / diagnostic foundations

| Term | Plain explanation |
|---|---|
| SOC | The team/department that does security monitoring. |
| SIEM | The platform that collects logs and correlates/detects on them (e.g. Elastic, Splunk). The R1–R8 rules live here. |
| EDR | A mechanism for detecting and responding to suspicious behavior on endpoints/servers. |
| Sigma | A vendor-neutral, shared format for detection rules; converted to each SIEM's own query language before use. |
| Falco | An open-source tool (uses eBPF) that detects container/host runtime behavior. |
| Elastic / Datadog | Log analysis and monitoring platforms. This repo's `summarize.py` can output in these formats too. |
| Semgrep / Trivy / gitleaks | Tools for code analysis / vulnerability & misconfiguration scanning / secret detection, respectively. |
| ZAP / nmap | Standard tools for web-app testing and port scanning, respectively. |
| SARIF | The standard format for static-analysis results. Tools like CodeQL emit it; `vuln_triage` can ingest it. |
| zgrab2 | The ZMap project's application-layer scanner. Actually connects to a target and records responses (banners, TLS, etc.) as JSON Lines. It has no built-in scope limit, so use it only on assets you own (`scripts/zgrab2_guard.py` narrows the target list). |
| JSON Lines | A format with one JSON object per line (what zgrab2 and similar tools emit). `vuln_triage` can read it as-is. |

## Vulnerability / disclosure terms

| Term | Plain explanation |
|---|---|
| CVE | The globally shared ID number assigned to a published vulnerability (e.g. CVE-2026-59310). |
| CVSS | A vulnerability's severity score (0–10). 9.0+ is Critical. |
| Security advisory | A vendor's official notice: "this product has this vulnerability, here's how to fix it." |
| VMSA | VMware's (Broadcom's) name for its advisories (e.g. VMSA-2026-0006). |
| GHSA | A GitHub Security Advisory — commonly seen for library vulnerabilities. |
| Dependabot | A mechanism that automatically finds and flags known vulnerabilities in dependency libraries. |
| Management plane | The entry point used to administer a device or service (e.g. vCenter, ESXi, VAMI, BMC/IPMI). An unauth RCE here is especially dangerous. |

## Sandbox-related

| Term | Plain explanation |
|---|---|
| Sandbox | An isolated, disposable execution environment — breaking it doesn't affect anything else. |
| Ephemeral | The property of being rebuilt fresh on every start and discarded on exit. Prevents an attacker from persisting, but doesn't remove the underlying weakness itself. |
| re-instantiate ≠ re-implement | "Spun up fresh each time" is not the same as "rewritten from scratch each time." It just means a new instance is built from a fixed recipe. |

---

## MITRE ATT&CK (supplementary)

**The de facto world standard for classifying cyberattack techniques.** A "T-number" is the shared code assigned to each technique within it.

- Published and maintained by **MITRE** (a US non-profit). **Free and open** for anyone to use.
- A systematic catalog of techniques actually observed in real attacks. Used as a common language by nearly every SOC/EDR/SIEM/threat-intel vendor and practitioner.
- Structure: **Tactics** (the goal, `TA####`) contain **Techniques** (the method, `T####`), which can have **Sub-techniques** (`T####.###`).
  - Example: under the tactic "Command and Control," technique `T1071 Application Layer Protocol`, under which `T1071.001 Web Protocols`.

### Mapping to this repo's R1–R8 (main ones)

> **R1–R8 are this repo's own organizing labels** (not a well-known standard on their own). The underlying *behavior* each one detects maps cleanly onto established MITRE ATT&CK techniques.
> When explaining this externally, cite the ATT&CK **T-number alongside the R-number** so it's understood universally. See [`defense-detection-notes.md`](defense-detection-notes.md) §3 for the full mapping.

| T-number | Technique (rough gist) | Tactic | This repo's R |
|---|---|---|---|
| T1595 | Active Scanning (actively probing from outside) | Reconnaissance | R3 |
| T1046 | Network Service Discovery (internal service enumeration) | Discovery | R3 / R2 |
| T1059 | Command and Scripting Interpreter (running commands/scripts) | Execution | R7 / R2 |
| T1071 | Application Layer Protocol (C2 over an application-layer protocol) | Command and Control | R4 |
| T1053 | Scheduled Task/Job (persistence via cron/timers) | Persistence | R5 |
| T1505.003 | Server Software Component: Web Shell (planting a web shell on a web server) | Persistence | R8 |

### Why citing both is stronger
- "R4" alone only means something to people inside this repo, but writing `T1071` lets anyone cross-reference it directly against analysts, products, and documentation worldwide (a shared language).
- Conversely, ATT&CK is a "dictionary of techniques," not a concrete detection rule or a product — it's a map of *what to look for*, while *how to write the detection* is left to Sigma/Falco/etc.
- That's why **R1–R8 (concrete rules) and ATT&CK (shared taxonomy) play different roles, and work best together**.

### A caution (against overclaiming)
- ATT&CK is **an organized record of observed techniques, not an exhaustive answer key**. Techniques it doesn't list exist, and a single attack commonly spans multiple T-numbers.
- "Mapped to ATT&CK" does not mean "defended." Use it as **a map for inventorying which techniques you do and don't have visibility into** — a dictionary of techniques, not a concrete rule or product (the "how to write it" part is still Sigma/Falco/etc.'s job).

---

> As new terms come up, add a row to this table each time — that way "what was that thing again" always has one place to look it up.
