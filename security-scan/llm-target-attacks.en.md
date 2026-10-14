# Attacks on LLM systems themselves (a defensive view)

日本語: [`llm-target-attacks.ja.md`](llm-target-attacks.ja.md)

> ⚠️ **This document widens the repository's scope.** The subject matter so far has been "**AI agents used to attack**" (Strix/Cairn/Hermes in the Gambit case).
> From here, it covers the other direction: "**a system built on an LLM becomes the target**." This is for organizations that use an LLM or AI agent and need to defend it, not for running an attack.
> The policy is unchanged: **detection and defense design only, no attack reproduction (payloads, exploit code).**

## 1. Four patterns (confirmed against primary sources)

| Pattern | Case confirmed from a primary source | OWASP Top 10 for LLM (2025) |
|---|---|---|
| A. Prompt injection → execution with the agent's privileges | §2 below | **LLM01** (Prompt Injection) + **LLM06** (Excessive Agency) |
| B. System prompt leakage | §3 below (PLeak) | **LLM07** (System Prompt Leakage) |
| C. Indirect prompt injection (via external content) | §4 below (EchoLeak) | A variant of **LLM01** + **LLM02** (Sensitive Information Disclosure) |
| D. LLMjacking (abuse of stolen cloud credentials) | §5 below (Sysdig) | **LLM10** (Unbounded Consumption) |

> This repository's existing framework (R1–R8, G1–G6) is designed to **observe the network and hosts to detect an autonomous offensive agent**. Defending the LLM system itself (prompt design inside the app, output validation) is a different observation point. Overlaps are noted in §6.

---

## 2. Prompt injection → execution with the agent's privileges

Cases confirmed from primary sources (each is a **specific vendor/product implementation flaw**, not a generic LLM defect).

| Case | Content (high level) | Source |
|---|---|---|
| **EchoLeak** (CVE-2025-32711) | Microsoft 365 Copilot. CVSS 9.3. Details in §4 | Microsoft, Aim Security |
| **Semantic Kernel** (CVE-2026-26030, CVE-2026-25592) | Microsoft's agent framework; a plugin's filter function reportedly assembled strings unsafely, so a crafted prompt could reach code execution | Vendor advisories (reported secondhand; not independently confirmed) |
| **Context7 MCP server** (CVE-2026-75130) | Poisoned custom instructions reportedly let a connected coding agent steal credentials from environment files and delete files. CVSS 4.0 (6.4). Finder: Noma Security | VulnCheck (the CVE assigner) |
| **ModelScope ms-agent** (CVE-2026-2256) | v1.6.0rc1 and earlier. Prompt-derived input reaching OS command execution (command injection) | NVD |

**Prevent**:
- Do **not** build commands or code dynamically from agent-generated strings (avoid string interpolation and `eval`-style execution).
- **Allowlist** tool calls and minimize the agent's execution privileges (run containers as a non-root user, drop unneeded capabilities).
- Put a **human approval gate** in front of risky actions (file deletion, outbound sending, access to credentials).

**Detect**:
- An agent process spawning an **unexpected child process** (same idea as this repository's **R7**/**R8**: a process that should not normally be invoked, invoked in a short window).
- Whether audit logging exists on paths that receive instructions from outside, such as an MCP server (**G1**: skill install/auto-generation/self-modification; **G4**: audit log missing/stopped).

---

## 3. System prompt leakage (PLeak)

- **Primary source**: Hui, Yuan, Gong, Burlina, and Cao, "PLeak: Prompt Leaking Attacks against Large Language Model Applications" (arXiv:2405.06823).
- **Content**: using an attacker-controlled surrogate ("shadow") LLM, the method runs **gradient-based optimization** to automatically craft adversarial queries sent to the target application, recovering the system prompt token by token from the start. It reportedly outperforms hand-written queries and jailbreak-derived baselines. It was tested against real, publicly deployed apps on Poe, and the authors reported the issue to Poe.
- **What is not confirmed**: claims that "Trend Micro analyzed this" or that it "bypassed Azure AI Foundry's filters" **could not be confirmed against a primary source** (the paper, or the report to Poe). Searching turned up no reliable primary Trend Micro article, only pages that appear to be reposts. This is not treated as fact until it can be corroborated.

**Prevent**:
- **Do not put credentials or anything damaging if leaked into the system prompt.** Design on the assumption that a system prompt can eventually leak — it is not a secret store.
- Put an output filter/classifier in front of responses to check whether the system prompt appears verbatim.

**Detect**:
- A pattern of queries from the same source, **slightly varied and repeated in a short window**. The idea matches this repository's **R3** (burst detection of reconnaissance-style access) — only the target differs (enumerating web paths vs. repeated prompt probing).

---

## 4. Indirect prompt injection (EchoLeak, CVE-2025-32711)

- **Primary sources**: Microsoft's security advisory (CVE-2025-32711) and Aim Security's report. CVSS 9.3 (Critical). Microsoft classifies it as "AI command injection" that lets an unauthorized attacker disclose information over a network. Fixed in June 2025. No known in-the-wild exploitation is reported.
- **Content (high level)**: an attacker hides instructions in an email (as an HTML comment, or white text on a white background — invisible to a person). When the user later asks Copilot something unrelated, the **RAG mechanism** pulls that email in as context. Following the hidden instructions, Copilot embeds sensitive local information into an outbound reference link. This path reportedly evaded Microsoft's defensive classifier (XPIA) and link redaction, and used an allowed Microsoft domain to exfiltrate the data. Aim Security frames this as an "LLM scope violation" — a departure from the system's intended role.
- **Generalized pattern**: any system where an LLM can (1) ingest external, untrusted content and (2) take some action based on it (sending, calling a tool) carries the **same kind of risk**. In this repository's own terms, the defensive principle is to **always treat retrieved content as data, never as instructions**.

**Prevent**:
- **Always treat content retrieved from outside (email, web pages, documents) as data, not instructions.** This is the same principle this session itself follows when handling PR bodies or notification text from GitHub.
- **Allowlist** the destinations an LLM can send to (domains, tools) — applying this repository's **R1/R4** idea (watching server-side egress to LLM/messaging APIs) to egress from the LLM/agent itself.
- Strip hidden text (HTML comments, white-on-white text, zero-width characters) before it reaches the model.

**Detect**:
- An LLM/agent service account sending to a **domain it does not normally use** (same idea as R1/R4).
- Checking generated outbound links for parameters that look like sensitive data.

---

## 5. LLMjacking (abuse of stolen cloud credentials)

- **Primary source**: Sysdig Threat Research Team's reports (May 2024, with a follow-up in September 2024).
- **Content**: attackers stole cloud credentials from a **vulnerable Laravel instance (CVE-2021-3129)**. With those credentials, they enabled access to cloud-hosted LLMs (for example, Claude via Amazon Bedrock) and **resold that access** to other cybercriminals, while the bill landed on the victim's cloud account. Sysdig estimated that, left undiscovered, this could run to over $100,000 per day in LLM consumption costs. The September follow-up reported attackers tampering with logging, such as calling `DeleteModelInvocationLoggingConfiguration`, to delay detection.
- **Relation to the Gambit chain**: the root cause is the **same pattern as step ⑥ in the Gambit report** (over-broad Secrets Manager / IAM permissions combined with credential theft). Only the target — an LLM service — differs.

**Prevent**:
- Scope cloud IAM to **least privilege, limited to the specific LLM services/models in use** (same remedy as step ⑥).
- Keep credentials out of code and configuration files (catch this with gitleaks).
- Set **budget alerts** on cost and usage.

**Detect**:
- A sudden spike in cloud billing or usage (an anomalous number of LLM inference calls).
- Detecting, in cloud audit logs, **the act of disabling logging itself**. This maps almost directly to this repository's **G4** (audit log missing/stopped) as a real-world example.

---

## 6. Connection points to this repository's existing framework

| Pattern | Connection to the existing framework |
|---|---|
| A. Abuse of execution privilege | R7/R8 (unexpected process spawns), G1 (skill auto-generation), G4 (audit logging) |
| B. System prompt leakage | Same idea as R3 (burst detection of repeated access) |
| C. Indirect prompt injection | R1/R4 (watching egress to LLM/messaging APIs), applied to the agent's own outbound traffic |
| D. LLMjacking | Same pattern as step ⑥ of the Gambit chain (over-broad IAM), G4 (audit log missing/stopped) |

**This is only pointing out the connection, not an implemented detection rule.** No R1–R8 rule (Sigma/Falco/Elastic/Datadog) has been written for these four patterns. The layer that matters here — prompt design and output validation inside the application — sits outside what this repository's existing tools (netcheck, vuln_triage, the detection rules) observe.

## 7. Limits and what is unconfirmed

- The prompt-injection-to-execution cases (Semantic Kernel, Context7, ModelScope) rest on **vendor advisories and CVE database entries**. Nothing here was run to confirm it.
- The "Trend Micro" and "Azure AI Foundry" claims attached to PLeak are **not corroborated** (see §3).
- The LLMjacking cost figures are Sysdig's estimates; other articles cite different measurement windows and amounts. Check Sysdig's own posts (sysdig.com/blog) for the exact numbers.

## 8. References (primary and near-primary sources)

- Microsoft, CVE-2025-32711 (EchoLeak): https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711
- Aim Security's technical account of EchoLeak (via The Hacker News): https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html
- Academic post-mortem of EchoLeak (arXiv): https://arxiv.org/html/2509.10540v1
- Hui et al., PLeak (arXiv:2405.06823): https://arxiv.org/abs/2405.06823
- VulnCheck, CVE-2026-75130 (Context7 MCP server): https://fieldguide.lutrasecurity.com/CVE-2026-75130/
- NVD, CVE-2026-2256 (ModelScope ms-agent): https://nvd.nist.gov/vuln/detail/CVE-2026-2256
- Sysdig, LLMjacking (initial report): https://sysdig.com/blog/
- OWASP, Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/

> Detection and defense design only. No attack procedures or safety-bypass techniques.
