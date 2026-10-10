# Cyber Verification Program (CVP) readiness & application prep — English

日本語: [`cvp-readiness.md`](cvp-readiness.md)

Maps this project (`ai-agent-attack-defense`: defensive research and small tools built around the Gambit report's
Strix/Cairn/Hermes) to Anthropic's [Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program)
(CVP), and says which tier to consider.

> **Source & freshness**: reflects the official page (published 2026-10-06) as checked on **2026-10-10**. The program can change —
> re-check the official page before applying. Where the page is silent we say "not stated" rather than guess.

---

## 1. The three tiers (as stated officially)

| Tier | For | Scope | Applicant | Review |
|---|---|---|---|---|
| **Defense Access** | Defensive work (SOC, incident response, malware reverse-engineering, vulnerability analysis/validation) | Reduces the blocking classifiers for defensive work | **Organizations** (security teams at companies, nonprofits, universities, government; critical-infrastructure operators; smaller security firms; OSS maintainers) and **individual researchers "with a track record of reported vulnerabilities"** | aims for "a few days" |
| **Red Team Access** | Authorized penetration testing and red-teaming (includes everything in Defense) | **Only systems the organization is authorized to test.** Actions that could cause physical harm or mass disruption — deploying ransomware, damaging physical systems, **pen testing high-risk safety systems** — stay blocked | **Organizations only** (in-house/government red teams, pen-testing firms). **Individuals are not eligible** | "a few weeks"; **enrolled in Defense Access during review** |
| **Specialized Access** | A limited set of verified organizations authorized to test safety systems that could affect lives or markets (flight OS, power grids, telecom, interbank transfer, government administrative networks) | Fewest cyber blocks | Organizations; **every org is reviewed in depth in collaboration with the US government** | not stated |

### Common points
- **Models**: every tier includes Claude Opus 5.5 / Sonnet 5.5 / Mythos 5.1 and future models.
- **What generally available models can already do**: GA models (Opus 5.5 / Fable 5.1 / Sonnet 5.5) conservatively block most cyber work, but remain usable for
  **code review, patching known issues, finding vulnerabilities in your own source code, and triaging security alerts** → these need **no CVP**.
- **Applying**: portal https://portal.anthropic.com/programs/cvp . **All applicants are verified** and must provide **proof of the security controls required for the tier**
  (specific documents are not stated).
- **Data retention**: enrolled organizations must **retain data** so Anthropic can monitor for cyber misuse. Enterprise Frontier Safeguards (EFS — zero-retention privacy plus
  safeguards, data in infrastructure you control) is expected **"later this fall"**. Until then, orgs with **zero-data-retention access to Fable 5.1 / Mythos 5.1 can use CVP with ZDR**.
  EFS interest form: https://claude.com/form/enterprise-frontier-safeguards
- **Platforms**: Claude Platform / Google Cloud Vertex AI / Microsoft Foundry. Amazon Bedrock only for EFS-eligible customers.
- **Existing members**: existing CVP members keep prior settings and are automatically evaluated for the new models; existing Project Glasswing members move to Specialized Access (no re-approval for current models).
- **Workspaces**: admins assign access to specific workspaces ([Claude Console support article](https://support.claude.com/en/articles/16764810-assign-a-program-to-workspaces-in-claude-console)).
- **False-positive blocks / rejection appeals**: https://claude.com/form/cyber-block-false-positive-report-cvp-rejection-appeal

---

## 2. Activity → tier mapping

| Activity (this repo) | Nature | Tier |
|---|---|---|
| `vuln_triage.html` / `scripts/summarize.py` (result aggregation/triage; ingests SARIF / netcheck / zgrab2) | defensive (vulnerability analysis/validation) | **Defense** |
| `netcheck/` (confirmation-only, no attack), `scripts/zgrab2_guard.py` (restricts scanner targets to an allowlist) | defensive | **Defense** |
| `security-scan/detections/` (Sigma / Falco / Datadog / Elastic rules R1–R7) | defensive (detection design) | **Defense** |
| `.github/workflows/security-scan.yml` (Semgrep/Trivy/gitleaks CI) and the consistency check that blocks drift | defensive (code/dependency validation) | **Defense** |
| **Static** analysis of Strix / Cairn / Hermes / ARTEX (`*-notes.md`, `artex-analysis.*`) | defensive (attack-tool analysis) | **Defense** |
| Strix local-execution PoC (`strix-local-poc/`, static analysis of benign code) | defensive / research | **Defense** |
| Running Cairn against an authorized lab target (`cairn-lab/`) | offensive testing | **Red Team** (org only) |
| Testing safety-critical systems | safety-critical | **Specialized** (if applicable; with US gov) |

**Reading**: most current artifacts fall under **Defense**. Only actively running offensive harnesses against authorized targets needs **Red Team** (an org application).

---

## 3. Application prep: what this repo can and cannot show

CVP asks for proof of required security controls (documents not specified). What the repo can show today:

- **Responsible use**
  - README / SECURITY.md / CONTRIBUTING.md state "**owned or authorized targets only**" and "detection/defense design only". License: MIT.
  - `netcheck` refuses out-of-range targets **before** running, requires consent, uses a localhost-only token, and logs runs. `scripts/zgrab2_guard.py` reuses the same rule and
    **emits nothing if any single target is out of range**.
  - Attack-tool analysis is **static review only (nothing is built or run)**, and the policy not to reconstruct attack recipes or safety-filter removal is documented (Hermes / ARTEX analyses).
- **Isolation / operational controls**
  - `cairn-lab/cairn-authorized-lab-runbook.md`: preconditions checklist, network isolation, egress limits, throwaway/snapshot, monitoring, do-not list.
  - `cairn-lab/dispatch_mock_local.yaml`: **no-attack** engine-only verification.
- **Technical verification capability**
  - `strix-local-poc/` (repro steps, patch, logs), `detections/` (R1–R7), `shared/taxonomy.json` + CI consistency check.
- **Secret management**: `.gitleaks.toml` / `.pre-commit-config.yaml`; CI is green.

**What it cannot show (honestly)**

- **For an individual applying to Defense, the stated criterion is "a track record of reported vulnerabilities".** This repo is defensive research and tooling —
  **it is not a substitute for vulnerability-report history.**
- Organizational identity and controls (for Red Team).
- Whether you can **accept data retention and monitoring** (consider this if you handle confidential or NDA work).

> Keep secrets (LLM keys, etc.) out of commits.

---

## 4. Recommended actions

1. **First ask "do I need CVP at all?"** Code review, triaging scan results and alerts, finding vulnerabilities in your own code, and writing defensive rules are
   officially possible on generally available models. Much of the current work falls here, so CVP is **not urgently required**.
2. **If you, as an individual, want Defense Access**: the criterion is a track record of reported vulnerabilities. If you don't have one yet, consider
   (a) building one through legitimate reports within your own assets / authorized scope / bug-bounty programs, or
   (b) applying through an organization. Attach this repo as **supporting evidence of controls, responsible handling and technical skill** (review targets a few days).
3. **If an organization will run authorized-lab or production pentests → Red Team Access** (org application, a few weeks; Defense during review).
   Preconditions: target ownership/written authorization, an isolated lab, and meeting data-retention requirements. Submit the §3 isolation design, runbook and mock verification as proof of controls.
4. **Decide the data-retention question first**: retention for monitoring is the baseline. If you need zero retention, check ZDR access to Fable 5.1 / Mythos 5.1, or EFS (expected later this fall).
5. **Unchanged red line**: even under Red Team, actions that could cause physical harm or mass disruption (ransomware deployment, damaging physical systems, pen testing high-risk safety
   systems) stay blocked — consistent with this project's policy (build no attack recipes or safety-bypass).

---

## References

- [Anthropic — Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program) (published 2026-10-06)
  - Merges Project Glasswing and the prior CVP; "cybersecurity is inherently dual use", so access is limited to vetted defenders.
  - Glasswing results: partners reported **at least 129,000** verified software vulnerabilities (Apr–Jul 2026); Anthropic's own open-source scanning found 5,500 more (Apr–Oct 2026);
    **33,000+ rated critical/high**. The page calls these an **undercount**, estimating true impact "at least five times higher".
  - CyScenarioBench (Opus 5.5; 10 challenges × 5 attempts = 50 trials per tier): without CVP every task is blocked on the first prompt; Defense blocked 46 of 50 trials at some point
    (4 succeeded); Red Team had no blocks and completed 34 of 50 ("effectively equivalent" to no safeguards). → **Defense is designed to stop malicious multi-stage attacks.**
- Apply: https://portal.anthropic.com/programs/cvp · Tier details (Help Center): https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet
