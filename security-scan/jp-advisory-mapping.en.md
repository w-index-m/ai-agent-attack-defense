# Japanese advisories and this repository: a mapping

日本語: [`jp-advisory-mapping.ja.md`](jp-advisory-mapping.ja.md)

From October 7 to 9, 2026, the Personal Information Protection Commission, JPCERT/CC, the National Cybersecurity Office, IPA, and others published advisories in response to a series of unauthorized-access incidents leaking personal information at Japanese organizations.
This page lines them up against this repository's defenses. **It is limited to defensive organization and contains no attack procedures.**

> ⚠️ Sourcing (updated 2026-10-12):
> - The text of **JPCERT/CC advisory JPCERT-AT-2026-0030** (published 2026-10-08, updated 2026-10-09: overview, techniques and traces, countermeasures, references) was checked against the **original text pasted by the user**. Cases A–D in §1 and §4 are based on it. For case C, the body of **JPCERT-AT-2026-0023** (2026-08-14) was also checked against the original pasted by the user (§4.1).
> - **The Personal Information Protection Commission's case 9** in §1 is **secondary information** from a blog summary (piyolog, 2026-10-11). The Commission's original (WARNING revised October 7) has not been checked.
> - The advisory states that the same technique is not necessarily used in every incident, that the information grasped is "limited and fragmentary," and that it will be updated as new information emerges. Confirm the latest details in the original.

## 1. The four patterns and the Commission's cases

**Overview (summary of the original)**: Around September 2026, leaks of personal information through unauthorized access have been occurring one after another at Japanese organizations, across multiple products and services. The advisory covers an attack type, separate from ransomware and similar, that leads to large-scale leaks. **Besides apps for general users, systems not meant to be accessed by an unspecified public, such as BI tools and employee-facing management systems, have also been hit.**

The four cases JPCERT/CC presented (high level only):

| Case | Content (based on the original) |
|---|---|
| A | **Scanning each target for various known vulnerabilities** and trying to exploit them. Attacks abusing administrative weaknesses that are not vulnerabilities (**theft of configuration or backup files**) may also be attempted. Suspicious source IP addresses were added on October 9 |
| B | **Unauthorized operations through APIs**, with information tampered with via requests to an app's management API. Reported techniques: (a) analyzing a public smartphone app to identify API details; (b) attacking internal APIs that the UI cannot reach (changing user permissions, creating unauthorized accounts, observing differences in authentication responses, identifying account information through NoSQL injection); (c) using API keys stolen from another system's compromise. Suspicious source IP addresses were added on October 9 |
| C | **A SQL injection vulnerability in Metabase (CVE-2026-72898)**. A crafted request sent without authentication runs malicious SQL against the application database and can lead to admin access. Abused through unauthorized API requests. **Per Metabase, zero-day attacks have been confirmed** (JPCERT-AT-2026-0023). Exploitation is described as between early August and early September. On the same day Metabase also published **a different** SQL injection (CVE-2026-72899, via a publicly shared dashboard; GHSA-r8h2-qpfx-mx59) (§4.1) |
| D | **A WAR file placed on an application server reachable from a public web server** (added October 9). A JSP in the WAR acts as a malicious simple web shell: it takes a specific query parameter and runs it as a shell command. Repeated GET and POST requests to the web shell were observed around September |

The original lists **suspicious source IP addresses and example User-Agents** for each case. The IP addresses carry notes that they were used only in limited periods and may have been legitimate. This repository **does not copy them** (they age and cause false positives). For investigations, use the original (§5).

The confirmation of zero-day attacks is stated not in JPCERT-AT-2026-0030 but in **JPCERT-AT-2026-0023** (as Metabase's information). The blog's (secondary) "zero-day exploitation confirmed" was correct on this point.

The Commission (WARNING revised October 7) classified breach incidents into nine cases. Case 9, "API abuse," was a state where, because of API design or configuration flaws, rewriting a parameter after login returned other users' information.

## 2. Mapping

The "This repository" column reflects the current state of documents and tools (checked 2026-10-12). **Nothing has been verified on real hosts.**

| Pattern | Prevent | Detect | State in this repo | Gap |
|---|---|---|---|---|
| A: probing for known vulnerabilities | Prioritized patching, reduced exposure | External enumeration (R3) | OS update checks (`os_patch_check_*`), Trivy, netcheck, R3 | Per-product exploitation detection |
| A: admin weakness (config / backups) | Do not place them where the web can reach | Access to such files under the web root | Items added in playbook §3A-D. **netcheck now checks 15 items** (`.env`, `.git`, DB dumps, backups, and so on; not yet run on real hosts) | No detection of access to such files |
| B: API abuse (broken authorization) | Check authorization per user on the server | API-log anomalies (bursts, 401/403 spikes) | Items added in playbook §3A-A | **No detection rules**, and no tool for auditing API authorization |
| B: API-key abuse | Narrow key scope, rotate regularly | Key-use anomalies | gitleaks, playbook §3A-B | Key-use detection; decoys (§5 is a design only) |
| C: BI-tool vulnerability (Metabase, CVE-2026-72898 / 72899) | Upgrade; do not expose (VPN / IP restriction); as a workaround, block `/api/session/reset_password` | External access to admin ports (R3). Compromise signs are a log pattern (§5) | netcheck, playbook §3A-C (measures for both CVEs) | No rule for the log pattern (POST 400 → GET 200). No product-specific detection |
| D: Web-shell placement | Upload allowlist, no execute permission, read-only web root | New files in the web root; child processes under the web server | Playbook §3 ③, **R8** (two Sigma / Falco rules: placement, and a shell spawned by a web server) | Elastic / Datadog versions are not implemented; not validated in a real environment; full FIM operation is separate |
| Case 9: API abuse | Same as pattern B | Same as pattern B | Playbook §3A-A | Same |

## 3. Gaps, in priority order

1. **API authorization checks and detection.** Pattern B and case 9 are the weakest area in this repository. First, add per-API authorization checks to your operating procedures.
2. **Exposure of configuration files and backups.** Implemented in `netcheck` (15 items). Validation on real hosts is the next task.
3. **Web-shell placement detection.** R8 is implemented for Sigma and Falco. The Elastic / Datadog versions and tuning/validation in a real environment remain.
4. **Preparing for product-specific exploitation, such as BI tools.** Case C's CVE-2026-72898 and CVE-2026-72899 are **separate vulnerabilities** (published by Metabase on the same day). Confirm you run a version that includes the fixes for both. The basics are reduced exposure and prioritized patching. For case C, you need to confirm patching of the application itself (`os_patch_check_*` covers the OS only, not apps such as Metabase).

## 4. Countermeasures JPCERT/CC recommends, and how this repository maps

Based on the techniques reported to it, JPCERT/CC recommends the following (summarized; see the advisory for the original wording). For details on API access, it points to OWASP guidance.

**Against access through APIs**

| Recommendation | State in this repo |
|---|---|
| Limit the number of requests per unit time to prevent repeated or bulk access | Added to playbook §3A-A (rate limiting). No implementation or detection |
| Set separate rate and usage limits on high-load or high-abuse functions (login, password reset, SMS sending, search) | Same |
| Enforce access control on every endpoint, including non-public ones, accepting only permitted users and HTTP methods | Added under §3A-A (authorization) |
| Grant API users and tokens only the minimum necessary permissions | Added to §3A-B |
| Give API tokens a suitable expiry; avoid long-lived tokens | Added to §3A-B |
| Be able to quickly revoke tokens that are no longer needed or suspected leaked | Added to §3A-B (respond) |

**General countermeasures**

| Recommendation | State in this repo |
|---|---|
| Restrict access by region if the service's users are regionally limited | Added to §3A-E |
| Apply fixed updates if running versions affected by known vulnerabilities | OS update checks, Trivy, playbook §3A-C |
| Review lateral-movement countermeasures for after a web server or similar is compromised | Steps ④⑤⑥ of the chain (§3) and §3A-E |
| Review the intrusion-detection setup and first-response procedure | Detection rules R1–R8 (network and host), playbook §4. No API-log detection |
| Prepare customers in peacetime against secondary harm after a leak (for example multi-factor authentication) | Added to §3A-E |
| Stop exposing services or functions (such as admin features) that are not needed for the business | netcheck, playbook §3A-C |
| Do not keep data past its legal or contractual retention period or purpose | Added to §3A-E |

JPCERT/CC notes that systems not meant for an unspecified public (employee-facing systems, BI tools) have also been hit, and recommends the same review for them.

### 4.1 Case C (Metabase): summary of JPCERT-AT-2026-0023 (checked against the original)

- **Content**: On 2026-08-06 (JST) Metabase published a SQL injection vulnerability (CVE-2026-72898). A crafted request sent without authentication runs malicious SQL against the application database and can lead to Metabase admin access.
- **Exploitation**: Per Metabase, zero-day attacks have been confirmed. Several overseas organizations have disclosed damage, and there is information that it was exploited on August 2. Information that appears to be a PoC has also been seen, so attacks may spread.
- **Affected**: before x.63.5 on the 63 line, x.62.9 on 62, x.61.11 on 61, x.60.17 on 60, x.59.21 on 59, and x.58.24 on 58. Versions before the 58 line are not affected. Metabase Cloud is already mitigated.
- **Countermeasure**: upgrade to the latest version.
- **Workaround**: until you can upgrade, block access to `/api/session/reset_password` at network devices.
- **Compromise investigation**: if that endpoint was reachable from the internet, do not stop at upgrading; check for compromise. In the logs of Metabase or network devices, `POST /api/session/reset_password` (HTTP 400) followed by `GET /api/user/current` (HTTP 200) indicates a likely compromise. If compromise is possible, check user sessions, API keys, and admin accounts, change the credentials of connected databases, and review logs.
- **Metabase's own advisory (GHSA-vwf4-m7j8-wcjf), confirmed against the original (pasted by the user)**: Critical. The vendor states that **active exploitation was confirmed**. The workaround (block `/api/session/reset_password`), the post-upgrade steps (delete every row of `core_session`; review API keys and administrator accounts; rotate the credentials of connected databases; review logs), and the fixed versions (58.24 / 59.21 / 60.17 / 61.11 / 62.9 / 63.5) match the JPCERT/CC original. The CVSS 10.0 figure is from a summary. **The log pattern (POST 400 → GET 200) is not in this advisory's original**; it is what JPCERT/CC gave as Metabase's information (the source may be Metabase's announcement, unconfirmed).
- **A separate vulnerability (CVE-2026-72899, GHSA-r8h2-qpfx-mx59), confirmed against the original (pasted by the user)**: Metabase published it on the same day. An unauthenticated attacker can run SQL through a publicly shared card or dashboard that exposes a field-filter parameter and gain admin access (public sharing is enabled by default). The affected and fixed versions are on the same lines as 72898 (x.58.24 / 59.21 / 60.17 / 61.11 / 62.9 / 63.5). The interim measure is to disable public sharing or unpublish the relevant public links. **The original does not state that exploitation was confirmed.** JPCERT/CC has confirmed that information that appears to be a PoC for it has also been published.

**Scale of impact (Wiz Research article, 2026-08-10, summarized)**: disclosed 2026-08-06 as active (zero-day) exploitation against Metabase Cloud; affected companies — Framework, Tally, n8n, Kilo Code (Anaconda), ChecklyHQ, and others — disclosed impact between August 7 and 10. Per Wiz's observations, roughly 13% of cloud environments run a self-hosted Metabase instance, and about 25% of those are fully internet-accessible; roughly 2,500 instances are indexed on Shodan. By noon UTC on August 10, public PoC exploits had been open-sourced. **That article includes a reproduction of the vulnerability (decompiled code, request construction), which this repository does not adopt** (per the policy of including no attack reproduction steps). Only the scale facts are recorded here, to support the case for reducing exposure (via netcheck).
- The example User-Agent `Metabase-GHSA-vwf4/2.0` in advisory 0030 corresponds to the ID of CVE-2026-72898's advisory (GHSA-vwf4-m7j8-wcjf).

**References** listed in the advisory (URLs as given; contents not verified)
- OWASP Top 10 API Security Risks 2023: https://api-security.owasp.org/editions/2023/en/0x11-t10/
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- JPCERT/CC, advisory on the Metabase SQL injection vulnerability (CVE-2026-72898) (JPCERT-AT-2026-0023): https://www.jpcert.or.jp/at/2026/at260023.html (details for case C; cited in JPCERT-AT-2026-0030; **original checked**: §4.1)
- Macnica Security Research Center, "On the string of information-leak incidents from web systems": https://security.macnica.co.jp/blog/2026/10/web-incidents2026.html

JPCERT/CC asks for information about suspicious access or suspected compromise, techniques, and causes. The advisory lists a contact point for incident-response consultation.

## 5. Investigating a compromise (indicators)

JPCERT/CC lists, "for use in compromise investigation," **suspicious source IP addresses** (per case) and **example User-Agents** (cases B and C) in the original.

- Search your own access logs (web server, API, proxy, BI tool, and so on) **for the IP addresses and User-Agents in the original**. The IP addresses carry notes on the period they were abused (early August to early October), so look at **logs from that period**.
- A match may be **legitimate use** (the original says so). A non-match does not prove there is no compromise.
- User-Agents (`curl/…`, `python-requests/…`, ordinary browsers) are **weak signals on their own**. They only indicate automated clients and must not be the basis of a detection.
- For case C (Metabase), look in the logs of Metabase or network devices for **`POST /api/session/reset_password` (400) followed by `GET /api/user/current` (200)** (§4.1). This is the compromise sign Metabase gave; **do not judge on a single entry, look for the sequence**.
- For case D, check the application server behind the public web server for **placement of `.war` and `.jsp` files** and for **traces of a shell being started** under it (detection: R8).

## 5A. Private-sector analysis: Macnica (stats/trends) and Scutum (technical confirmation of AI agents)

> This section is based on **private-sector technical blogs**, not the official JPCERT/CC or Personal Information Protection Commission announcements. Confirmed against the original text pasted by the user.

### Macnica Security Research Center (Yutaka Sejiyama, published 2026-10-07, updated 2026-10-08)

- **Case count trend**: disclosures of this kind went 62 (2024) → 84 (2025) → 119 as of October 6, 2026 (265 total). **About 68% of this year's 119 (81 cases) cluster after July.**
- **Shift in targeted sites**: previously card data from EC sites was the focus; now targets range widely and indiscriminately — library catalog search, sightseeing-train seat reservations, university facility bookings, and more.
- **Breakdown of technique** (the 81 cases since July): ① known vulnerabilities in common software, 9 cases; ② credential abuse, 4; ③ flaws in site configuration/access control, 3; **④ insufficient explanation to classify, 65 (80.2%)**. Few disclosures identify the root cause.
- **What incident response/log analysis actually showed**: not a single targeted vulnerability, but **broadly probing an entire site, exercising screens and APIs normally while looking for flaws**. Some cases involved reverse-engineering a mobile app to extract an API key. Recon and exploitation are not always clearly separated.
- **On AI involvement (as of this article)**: "**no exploitation of a zero-day vulnerability has been confirmed**"; AI use "is hard to rule out, given the breadth and speed of the probing, but **cannot be confirmed**" either. This changes with Scutum's article below.
- **International picture**: 99 cases confirmed across 13 countries/regions, July–September 2026. South Korea: 30; France: 11; Poland: 8.

### Scutum (Secure Sky Technology / Bitforest, "Kanatoko," published 2026-10-14)

- **States explicitly that AI-agent involvement was technically confirmed.** Scutum built its own detection mechanism into its WAF to judge whether an attacker is an AI agent, and began monitoring the night of October 10, 2026. **By October 14 it had confirmed AI-agent attacks on Japanese companies' sites from at least three IP addresses.**
- **The detection method's details are withheld, to avoid enabling evasion.** Its stated property: "cannot enumerate every AI agent (false negatives possible), but a positive detection is essentially certain to be an AI agent (near-zero false positives)." It also states detection succeeded against all eight high-performance models it tested (this specific claim itself could not be independently verified).
- **Observed attack patterns (summarized; IP addresses are not reproduced here — see the original)**:
  - One IP showed only simple, high-volume scanning (classic behavior).
  - Another showed a textbook, staged pattern over roughly two-plus hours: **recon → exhaustive scanning of admin paths and backup files → SQL-injection attempts → automated submission to a contact form**, with **tools and techniques shifting by phase**.
  - A third ran for about eight hours, **shifting among many tools and techniques**: slow scan → fast scan → exploitation of known vulnerabilities → Nmap → login brute-forcing → exploitation of another known vulnerability.
  - **This matches the direction of this repository's R7** (one parent process running many security tools in rapid succession) — the timescale here is tens of minutes to hours rather than strictly "rapid," but the core signal (tools and techniques switching by phase) is the same. The scanned targets include `.git`, `.env`, `backup.zip`, `db_backup.sql`, overlapping with what `netcheck` §3A-D already checks for.
  - It states that the "mobile-app string in the User-Agent" pattern seen in large-scale A2B-style attacks was **not** observed across these three IPs.
- **Its conclusion on countermeasures**: whether or not an AI agent is involved, **the substance of defense does not change** (eliminate vulnerabilities; use a WAF that does not rely on signatures alone).

### Connection to this repository

| Observation | How it connects |
|---|---|
| A long-running, staged attack pattern where tools/techniques shift by phase | A real-world data point for R7. Worth considering whether R7's "short window" threshold should be loosened to match this case (tens of minutes to hours) |
| Scanning for `.git`, `.env`, backup files | `netcheck`'s §3A-D (configuration/backup exposure check) already covers the same kind of file |
| IP-based indicators | See the original (Scutum's blog). Not reproduced here (they age and cause false positives) |
| The AI-detection method itself | Scutum withholds it. It cannot be reproduced or verified |

## 6. Related files

- Defense playbook: [`defense-playbook.en.md`](defense-playbook.en.md) (§3A and §9)
- Detection concepts: [`defense-detection-notes.en.md`](defense-detection-notes.en.md)
- OS update checks: [`os-patch-check-notes.md`](os-patch-check-notes.md)
- Summary: [`security-summary.en.md`](security-summary.en.md)
