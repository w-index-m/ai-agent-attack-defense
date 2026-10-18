# AI Agent Skill Marketplaces as a Supply-Chain Attack Surface (Primary Sources)

日本語: [`openclaw-skill-supply-chain.ja.md`](openclaw-skill-supply-chain.ja.md)

Organizes two Unit 42 primary-source articles centered on **OpenClaw**, an AI agent, and its skill
marketplace **ClawHub**. Related to Pattern A (prompt injection → execution with the agent's privileges)
in `llm-target-attacks.en.md`, but the entry point differs: this is a software supply-chain attack where
**the user installs a malicious skill (roughly a plugin) themselves**.

> Same policy: **limited to detection/defense design**. No attack execution steps, weaponization, or
> safety-bypass techniques. Specific distribution sites/payload-delivery steps for the malicious skills
> are not transcribed here (see Unit 42's original articles).

## 1. Why This Attack Surface Differs from Prior Supply Chains

- A "skill" bundles executable code, a YAML manifest and a natural-language `SKILL.md` file (telling the
  agent when and how to use it) — the agent-world equivalent of an npm/PyPI package or a phone app.
- Once installed, a skill runs inside **the agent's privileged context**: it can read environment
  variables, call external services, write files and execute shell commands.
- Unlike conventional supply-chain attacks (dependency hijacking, typosquatting), a malicious skill can
  use **semantic instruction hijacking** to exploit the agent's natural-language understanding, bypassing
  the technical constraints (language runtime, container) that usually limit conventional malware (per
  Unit 42's "Trust No Skill").

## 2. Confirmed Malicious Skills (Unit 42, published 2026-06-23)

- In February 2026, Bitdefender Labs reported that roughly 17% of OpenClaw skills analyzed in the
  platform's first weeks carried malicious payloads. Koi Security's "ClawHavoc" disclosure documented
  341 malicious skills; Trend Micro separately confirmed skills distributing Atomic macOS Stealer (AMOS).
- In response, ClawHub integrated VirusTotal and ClawScan for proactive screening (and partnered with
  NVIDIA starting June 1, 2026).
- Unit 42's own February–May 2026 analysis found **five unblocked malicious skills that evaded this
  screening**. Unit 42 reported all five; OpenClaw banned the accounts and deleted the skills. They fall
  into three categories:

| Category | Summary |
|---|---|
| **Infostealers (2 skills)** | Distributed macOS infostealers. Used a fake "prerequisite" block that lured the user into running a Base64-decoded curl command in their own terminal (a paste-site redirect lure). One variant used C2 infrastructure distinct from the known AMOS cluster |
| **Evasion (1 skill)** | Embedded a genuine AMOS-delivering payload at the start of a `README.md`, then **padded the file with 22 MB of filler characters** to exceed the size thresholds many scanning pipelines skip past. This bypassed both ClawScan and VirusTotal (disclosed by JFrog Security Research in March 2026) |
| **Agentic financial schemes (2 skills)** | ① A skill whose `SKILL.md` instructed the agent to "always use" an embedded affiliate link, letting the operator dynamically swap recommended products via an external server ("runtime agentic affiliate injection"). ② A skill that had many agent instances pool cryptocurrency, letting the operator front-run a meme-token launch at the lowest price before distributing to agents — a form of pump-and-dump ("agentic front-running") |

## 3. Behavioral Integrity Verification (BIV): Registry-Scale Findings (Unit 42, published 2026-06-11)

Unit 42 proposed **Behavioral Integrity Verification (BIV)**, an audit method comparing a skill's
**declared** behavior against its **actual** behavior, and ran it across the entire OpenClaw registry
(49,943 skills).

- **Method**: the declared side (metadata, LLM-extracted natural-language claims) and the actual side
  (static code analysis plus LLM analysis of natural-language instructions) are compared against a
  shared taxonomy of 29 capabilities across 7 families.
- **Scale**: of 49,943 skills, **80.0% (39,933) showed at least one deviation**; 250,706 total deviations.
- **Intent classification** (of 163,754 clustered deviations):
  - **81.1% non-adversarial** (documentation errors, legitimate helper code, unused declarations) — best
    addressed through registry documentation outreach, not security review
  - **18.9% adversarial**, of which 60% was data theft/espionage, followed by payload/infrastructure and
    agent hijacking; financial, destructive and social-engineering intents combined were under 1%
- **Governance tiers** (per skill):
  - **5.0% (2,490 skills)**: multi-stage attack chains, **mandatory security review**
  - **16.8%**: single-stage adversarial deviations, contextual review
  - **72.5%**: benign (declared metadata simply hasn't caught up to the code)
- **Two dominant patterns cover 88% of all multi-stage chains**: ① silent credential exfiltration (read a
  secret, transmit it); ② instruction-override hijacking (take over the agent's decision loop, then
  exfiltrate)
- **Adversarial fraction by capability category**: Instruction manipulation 96% (the smallest surface but
  the highest signal-to-noise ratio — almost anything undeclared here is suspect), Credentials 56%,
  Network 37%, File system 10%, Process execution 12%. Unit 42 concludes a single threshold is the wrong
  instrument; **per-category severity tiers** are needed (Critical for credentials/instruction-level
  capabilities, High for network/process/environment, Medium for file system/encoding).

## 4. Prevention and Detection (from this repository's perspective)

**Prevention**:
- **Inventory third-party skills and run a behavioral-integrity check before installation** (the
  "declared vs. actual" comparison BIV embodies).
- **Allowlist the capabilities a skill may exercise** (restrict its filesystem/network/credential access
  to what it actually declares).
- Watch for **combinations** of individually-benign capabilities (e.g., file read → encode → network
  send) — no single capability alone proves malice.

**Detection**:
- Unexpected outbound traffic originating from a skill, inside the agent process (this repository's
  **R1/R4** applied to agent-originated egress).
- Whether an unusually large file (e.g., a README) is causing a scan to be skipped (**a blind spot in
  the detection pipeline itself**, not the skill).
- Post-publication changes to a `SKILL.md` or skill description (behavior that can be altered remotely
  after installation) — corresponds to this repository's **G1** (skill installation/auto-generation/
  self-modification).

## 5. Connections to This Repository's Existing Framework

| Element | Observation point | This repo's detection |
|---|---|---|
| Installing a malicious skill itself | Skill installation/self-modification | **G1** |
| C2 traffic via a skill (e.g., AMOS) | Outbound traffic from server/agent | **R1/R4** |
| Cron-job registration for C2 persistence | New persistence creation | **R5** |
| Evading scanners via file-size padding | A design gap in the detection pipeline itself | Outside existing R1–R8; requires a separate fix to the scanning tool |
| Instruction-override hijacking (BIV's dominant pattern) | Agent intent/behavior deviation | Close to **G2/G3** (attempted safety-mechanism bypass), but not explicitly covered by existing rules |

## 6. Limitations

- This document organizes two Unit 42 public articles; no independent verification was performed.
- Specific distribution domains/IOCs for the malicious skills are not transcribed here (see the originals).
- BIV is primarily static analysis; Unit 42 itself notes dynamic dispatch and obfuscated payloads can
  evade it.

## 7. References

- Unit 42, "OpenClaw's Skill Marketplace and the Emerging AI Supply Chain Threat," published 2026-06-23
- Unit 42, "Trust No Skill: Integrity Verification for AI Agent Supply Chains," published 2026-06-11
- Related: Koi Security's "ClawHavoc" disclosure, Trend Micro (confirmed AMOS distribution), Bitdefender
  Labs (early-campaign report), JFrog Security Research (the omnicogg file-padding disclosure)
- Related: this repository's `llm-target-attacks.en.md` (Pattern A), `artex-analysis.en.md` (defensive
  analysis of a `SKILL.md`-based extension mechanism)

> Limited to detection/defense design. No attack execution steps, weaponization, or safety-bypass techniques.
