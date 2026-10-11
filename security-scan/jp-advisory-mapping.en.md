# Japanese advisories and this repository: a mapping

日本語: [`jp-advisory-mapping.ja.md`](jp-advisory-mapping.ja.md)

From October 7 to 9, 2026, the Personal Information Protection Commission, JPCERT/CC, the National Cybersecurity Office, IPA, and others published advisories in response to a series of unauthorized-access incidents leaking personal information at Japanese organizations.
This page lines them up against this repository's defenses. **It is limited to defensive organization and contains no attack procedures.**

> ⚠️ Sourcing:
> - **§1–§3 (the four cases and the mapping)** are **secondary information**, based on a blog summary (piyolog, 2026-10-11) that the user shared as screenshots.
> - **§4 (JPCERT/CC's recommended countermeasures)** is based on the **original text** of the "countermeasures" and "reference information" sections of the JPCERT/CC advisory (published 2026-10-08; sections I and II were supplemented on 2026-10-09), as pasted by the user.
> - Confirm the accurate and current details, including the CVE number, in the primary sources: the full JPCERT/CC advisory and the Commission's WARNING (revised October 7).
> The advisory itself says the same technique is not necessarily used in every incident and that the information grasped is "limited and fragmentary."

## 1. The four patterns and the Commission's cases

The four cases JPCERT/CC presented (high level only):

| Case | Content |
|---|---|
| A | Probing each target for known vulnerabilities and attempting to exploit them. Administrative weaknesses that are not vulnerabilities (retrieval of configuration files or backups) can also be targeted |
| B | Unauthorized operations through APIs: learning API details from public apps, targeting internal APIs the UI never exposes, using API keys stolen from other systems |
| C | A SQL injection vulnerability in Metabase (the article gives CVE-2026-72898; zero-day exploitation reportedly confirmed), abused through unauthorized API requests |
| D | A WAR file placed on an application server reachable from a public web server (a JSP acting as a simple web shell). Added October 9 |

The Commission (WARNING revised October 7) classified breach incidents into nine cases. Case 9, "API abuse," was a state where, because of API design or configuration flaws, rewriting a parameter after login returned other users' information.

## 2. Mapping

The "This repository" column reflects the current state of documents and tools (checked 2026-10-11). **Nothing has been verified on real hosts.**

| Pattern | Prevent | Detect | State in this repo | Gap |
|---|---|---|---|---|
| A: probing for known vulnerabilities | Prioritized patching, reduced exposure | External enumeration (R3) | OS update checks (`os_patch_check_*`), Trivy, netcheck, R3 | Per-product exploitation detection |
| A: admin weakness (config / backups) | Do not place them where the web can reach | Access to such files under the web root | Items added in playbook §3A-D. **netcheck now checks 15 items** (`.env`, `.git`, DB dumps, backups, and so on; not yet run on real hosts) | No detection of access to such files |
| B: API abuse (broken authorization) | Check authorization per user on the server | API-log anomalies (bursts, 401/403 spikes) | Items added in playbook §3A-A | **No detection rules**, and no tool for auditing API authorization |
| B: API-key abuse | Narrow key scope, rotate regularly | Key-use anomalies | gitleaks, playbook §3A-B | Key-use detection; decoys (§5 is a design only) |
| C: BI-tool vulnerability | Do not expose (VPN / IP restriction), patch | External access to admin ports (R3) | netcheck, playbook §3A-C | Product-specific detection. **No item names Metabase** |
| D: Web-shell placement | Upload allowlist, no execute permission, read-only web root | New files in the web root; child processes under the web server | Playbook §3 ③, **R8** (two Sigma / Falco rules: placement, and a shell spawned by a web server) | Elastic / Datadog versions are not implemented; not validated in a real environment; full FIM operation is separate |
| Case 9: API abuse | Same as pattern B | Same as pattern B | Playbook §3A-A | Same |

## 3. Gaps, in priority order

1. **API authorization checks and detection.** Pattern B and case 9 are the weakest area in this repository. First, add per-API authorization checks to your operating procedures.
2. **Exposure of configuration files and backups.** Implemented in `netcheck` (15 items). Validation on real hosts is the next task.
3. **Web-shell placement detection.** R8 is implemented for Sigma and Falco. The Elastic / Datadog versions and tuning/validation in a real environment remain.
4. **Preparing for product-specific exploitation, such as BI tools.** The basics are reduced exposure and prioritized patching.

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
| Review the intrusion-detection setup and first-response procedure | Detection rules R1–R7 (network and host), playbook §4. No API-log detection |
| Prepare customers in peacetime against secondary harm after a leak (for example multi-factor authentication) | Added to §3A-E |
| Stop exposing services or functions (such as admin features) that are not needed for the business | netcheck, playbook §3A-C |
| Do not keep data past its legal or contractual retention period or purpose | Added to §3A-E |

JPCERT/CC notes that systems not meant for an unspecified public (employee-facing systems, BI tools) have also been hit, and recommends the same review for them.

**References** listed in the advisory (URLs as given; contents not verified)
- OWASP Top 10 API Security Risks 2023: https://api-security.owasp.org/editions/2023/en/0x11-t10/
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- Macnica Security Research Center, "On the string of information-leak incidents from web systems": https://security.macnica.co.jp/blog/2026/10/web-incidents2026.html

JPCERT/CC asks for information about suspicious access or suspected compromise, techniques, and causes. The advisory lists a contact point for incident-response consultation.

## 5. Related files

- Defense playbook: [`defense-playbook.en.md`](defense-playbook.en.md) (§3A and §9)
- Detection concepts: [`defense-detection-notes.en.md`](defense-detection-notes.en.md)
- OS update checks: [`os-patch-check-notes.md`](os-patch-check-notes.md)
- Summary: [`security-summary.en.md`](security-summary.en.md)
