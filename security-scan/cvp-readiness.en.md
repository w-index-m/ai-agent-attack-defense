# Cyber Verification Program (CVP) readiness & application prep — English

English mirror of `cvp-readiness.md`. Maps this project (`ai-agent-attack-defense`:
defensive research and small tools built around the Gambit report's Strix/Cairn/Hermes)
to Anthropic's [Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program).

## 1. The three tiers (summary)

| Tier | For | Scope | Applicant | Review |
|---|---|---|---|---|
| **Defense Access** | Defensive work (SOC/IR/malware analysis/vuln validation) | defense-tailored reduced restrictions | orgs **and individual researchers** | days |
| **Red Team Access** | Authorized pentest / adversarial assessment (incl. critical-infra IT) | offensive testing of authorized systems (physical-harm / mass-disruption / ransomware / safety-system actions stay blocked) | **orgs only** | weeks |
| **Specialized Access** | Orgs authorized to test safety-critical systems (flight/power/telecom/finance/gov) | near-minimal restrictions | org (**requires U.S. gov collaboration**) | — |

- All tiers access Claude Opus 5.5 / Sonnet 5.5 / Mythos 5.1, etc.
- Apply via the Anthropic portal; verification + proof of required security controls; data-retention
  monitoring is mandatory (zero-retention option planned with Enterprise Frontier Safeguards).

## 2. Activity → tier mapping

| Activity (this repo) | Nature | Tier |
|---|---|---|
| `vuln_triage.html` / `scripts/summarize.py` | defensive (vuln validation) | **Defense** |
| `netcheck/` (confirmation-only, no attack) | defensive | **Defense** |
| `.github/workflows/security-scan.yml` (Semgrep/Trivy/gitleaks) | defensive | **Defense** |
| Strix/Cairn/Hermes code & architecture analysis (`*-notes.md`) | defensive (malware/tool analysis) | **Defense** |
| Strix local-execution PoC (`strix-local-poc/`, static analysis of benign code) | defensive / research | **Defense** |
| Running Cairn against an authorized lab target (`cairn-lab/`) | offensive testing | **Red Team** (org only) |
| Testing safety-critical systems | safety-critical | **Specialized** (if applicable; U.S. gov) |

Most current artifacts fall under **Defense**. Only actively running the offensive harnesses
against authorized targets needs **Red Team** (org application).

## 3. Evidence of controls / responsible use

- **Responsible-use track record**: README states "authorized/owned targets only"; `netcheck`
  refuses out-of-range targets before running, requires consent, uses a localhost-only token, and
  logs runs (`netcheck.log`); documented policy not to reconstruct attack recipes or safety-filter removal.
- **Isolation/operational controls**: `cairn-lab/cairn-authorized-lab-runbook.md` (preconditions
  checklist, network isolation, egress limits, throwaway/snapshot, monitoring, do-not list);
  `cairn-lab/dispatch_mock_local.yaml` (no-attack engine smoke, verified).
- **Technical verification capability**: `strix-local-poc/` (repro steps, patch, verification logs).
- **Detection capability**: `defense-detection-notes.md` + `detections/` (Sigma/Falco/Datadog, R1–R7).
- **Secret management**: `.gitleaks.toml` / `.pre-commit-config.yaml`.

## 4. Recommended actions

1. **Individuals → apply for Defense Access** (review in days). Materials: this repo (defensive
   tools + analysis + responsible-use record + detection rules).
2. **Orgs doing real pentests → Red Team Access** (org application, weeks). Materials: §3 isolation
   design, runbook, mock verification as proof of controls. Preconditions: target ownership/authorization,
   isolated lab, data-retention requirements.
3. **Unchanged red line**: even under Red Team, physical harm / mass disruption / ransomware /
   safety-system actions stay blocked — consistent with this project's policy (build no attack
   recipes or safety-bypass).

## References

- [Anthropic — Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program)
  - Integrates Project Glasswing and the prior CVP.
  - Glasswing results: 129,000+ verified vulnerabilities (Apr–Jul 2026), 33,000+ critical/high.
  - CyScenarioBench: Defense blocked 46/50 multi-stage attempts; Red Team completed 34/50, matching no-safeguard performance.
