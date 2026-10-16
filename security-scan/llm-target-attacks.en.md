# Attacks on LLM systems themselves (a defensive view)

日本語: [`llm-target-attacks.ja.md`](llm-target-attacks.ja.md)

> ⚠️ **This document widens the repository's scope.** The subject matter so far has been "**AI agents used to attack**" (Strix/Cairn/Hermes in the Gambit case).
> From here, it covers the other direction: "**a system built on an LLM becomes the target**." This is for organizations that use an LLM or AI agent and need to defend it, not for running an attack.
> The policy is unchanged: **detection and defense design only, no attack reproduction (payloads, exploit code).**

## 1. Five patterns (confirmed against primary sources)

| Pattern | Case confirmed from a primary source | OWASP Top 10 for LLM (2025) |
|---|---|---|
| A. Prompt injection → execution with the agent's privileges | §2 below | **LLM01** (Prompt Injection) + **LLM06** (Excessive Agency) |
| B. System prompt leakage | §3 below (PLeak) | **LLM07** (System Prompt Leakage) |
| C. Indirect prompt injection (via external content) | §4 below (EchoLeak, plus the large-scale in-the-wild study in §4.1) | A variant of **LLM01** + **LLM02** (Sensitive Information Disclosure) |
| D. LLMjacking (abuse of stolen cloud credentials) | §5 below (Sysdig, plus "Double Agents" in §5.1) | **LLM10** (Unbounded Consumption) |
| E. Abuse of multi-agent sessions | §6 below (Agent Session Smuggling) | No clean existing category — a new pattern that exploits implicit trust between agents |

> This repository's existing framework (R1–R8, G1–G6) is designed to **observe the network and hosts to detect an autonomous offensive agent**. Defending the LLM system itself (prompt design inside the app, output validation) is a different observation point. Overlaps are noted in §7.

---

## 2. Prompt injection → execution with the agent's privileges

Cases confirmed from primary sources (each is a **specific vendor/product implementation flaw**, not a generic LLM defect).

| Case | Content (high level) | Source |
|---|---|---|
| **EchoLeak** (CVE-2025-32711) | Microsoft 365 Copilot. CVSS 9.3. Details in §4 | Microsoft, Aim Security |
| **Semantic Kernel — CVE-2026-26030** (Python SDK) | `InMemoryVectorStore`'s filter functionality failed to block dangerous attribute names from being used inside a filter expression, leading to remote code execution. CWE-94 (code injection). CVSS 9.9 (Critical). Fixed in 1.39.4 | **Confirmed against the original GitHub Security Advisory (GHSA-xjw9-4gw8-4rqx)** |
| **Semantic Kernel — CVE-2026-25592** (.NET SDK, a separate vulnerability) | `SessionsPythonPlugin`'s file download/upload functions (`DownloadFileAsync`, `UploadFileAsync`) did not sufficiently validate the supplied path, allowing writes to arbitrary locations. CWE-22 (path traversal). CVSS 9.9 (Critical). Fixed in NuGet 1.71.0 / pip 1.39.3 | **Confirmed against the original GitHub Security Advisory (GHSA-2ww3-72rp-wpp4)** |
| **Context7 MCP server** (CVE-2026-75130) | Poisoned custom instructions reportedly let a connected coding agent steal credentials from environment files and delete files. Sources disagree, giving CVSS 3.1 as 9.0 and CVSS 4.0 as 6.4. Finder: Eli Ainhorn, Noma Security. **Sources also disagree on whether a fix exists** (one says fixed in 2.1.3, another says unfixed as of August 2026) | Secondary sources only (NVD and VulnCheck could not be reached from this environment) |
| **ModelScope ms-agent — CVE-2026-2256** | Input validation in the Shell tool (named `check_safe()` and similar in secondhand sources) did not sufficiently sanitize prompt-derived input, leading to OS command execution. CWE-77. CVSS 3.1: 6.5 (Moderate). **As of 2026-03-04, no fixed version exists (Patched versions: None)** | **Confirmed against the original GitHub Security Advisory (GHSA-4gc2-344q-r2rw)** |

**Prevent**:
- Do **not** build commands or code dynamically from agent-generated strings (avoid string interpolation and `eval`-style execution).
- For any **tool that takes a file path** (download, upload, read, write), validate the supplied path against an allowlist so it cannot point outside the intended directory (defends against path traversal).
- **Allowlist** tool calls and minimize the agent's execution privileges (run containers as a non-root user, drop unneeded capabilities).
- Put a **human approval gate** in front of risky actions (file deletion, outbound sending, access to credentials).

**Detect**:
- An agent process spawning an **unexpected child process** (same idea as this repository's **R7**/**R8**: a process that should not normally be invoked, invoked in a short window).
- Whether audit logging exists on paths that receive instructions from outside, such as an MCP server (**G1**: skill install/auto-generation/self-modification; **G4**: audit log missing/stopped).

### 2.1 A framework-agnostic generalization (Unit 42, CrewAI/AutoGen study, 2025-05)

Unit 42 built **two functionally identical multi-agent investment-advisory apps** on two different
open-source frameworks, CrewAI and AutoGen, and demonstrated the same nine attack scenarios against
both. Their conclusion — **the vulnerabilities live in insecure design patterns, misconfiguration and
tool integration, not in either framework itself** — matches this repository's own stance that the tool
is neutral and what matters is design and governance.

| Scenario category | Summary (attack payload wording is not transcribed) | Primary mitigations |
|---|---|---|
| Enumerating participant agents / system prompts / tool schemas | Instructs the orchestrator ("don't delegate, answer directly") to reveal internal structure | Prompt hardening, content filtering |
| Unauthorized internal-network access (an SSRF variant) | Directs a web-reading tool at an internal private IP | Prompt hardening, content filtering, **tool input sanitization** |
| Sensitive-data exfiltration via a mounted volume | Directs a code-interpreter tool to search a host-mounted directory for high-entropy strings (credential-shaped data) and Base64-encode the output | Prompt hardening, **code-executor sandboxing**, content filtering |
| Service-account token theft via the cloud metadata service | Directs a code-interpreter tool to hit the cloud metadata endpoint (e.g., GCP's `metadata.google.internal`) with a specific header, retrieving the VM's service-account token | Same as above. **The same attack surface as the "Double Agents" case in §5 of this document** |
| Exfiltrating an entire DB table via SQL injection | Mixes a SQL-injection payload into a tool's input to dump a table containing other users' transaction history | Prompt hardening, tool input sanitization, **tool vulnerability scanning**, content filtering |
| BOLA (broken object-level authorization) access to another user's data | An innocuous-looking input (someone else's transaction ID) alone exploits a backend access-control gap | Tool vulnerability scanning (payload detection cannot catch this) |
| Indirect prompt injection exfiltrating conversation history | A web-reading tool loads an attacker-poisoned page whose embedded instructions direct the agent to send the conversation history to an external domain | Prompt hardening, content filtering. **See §4 of this document (the same EchoLeak-style construct)** |

Unit 42's five pillars of defense (see the source for full detail):
1. **Prompt hardening**: narrowly scope each agent's role/authority and explicitly refuse out-of-scope requests.
2. **Content filtering**: an inline defense layer inspecting input/output at runtime.
3. **Tool input sanitization**: a tool must never unconditionally trust its caller (the agent); check type, range and special characters.
4. **Tool vulnerability scanning**: run SAST/DAST/SCA regularly against every integrated tool.
5. **Code-executor sandboxing**: restrict container networking (block internal services and metadata endpoints), minimize mounted volumes, drop unneeded Linux capabilities, block dangerous syscalls, enforce resource quotas.

**No single mitigation is sufficient** — Unit 42's own conclusion is that defense-in-depth is required.

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

### 4.1 A Large-Scale In-the-Wild Study (Unit 42, 2026-03-03)

- **Primary source**: Unit 42 analysis based on real telemetry. Where most prior research stopped at
  proof-of-concept, this is notable for showing, at scale, **evidence that this is already being
  weaponized in the wild**.
- **Content**: attackers embed hidden instructions in web pages, which an LLM/agent unintentionally
  executes while summarizing or analyzing that page's content. Unit 42 proposes a taxonomy along two
  axes, **attacker intent** and **payload engineering**:
  - **Intent (by severity)**: Low (forcing irrelevant output, benign anti-scraping) / Medium (biasing
    hiring or review decisions) / High (bypassing AI ad review, SEO poisoning, forcing unauthorized
    transactions) / Critical (data destruction, leaking sensitive data or the system prompt, denial of
    service — e.g. a fork bomb)
  - **Prompt delivery methods**: visual concealment (zero font size, off-screen positioning,
    `display:none`, text matching the background color), obfuscation (embedding inside an SVG's CDATA
    section, hiding inside HTML attributes), dynamic execution (assembling the payload at runtime in
    JavaScript, delayed Base64 decoding)
  - **Jailbreak methods**: invisible characters, homoglyph substitution, payload splitting, repeating
    the instruction across multiple languages, JSON/syntax injection, and **social engineering that
    impersonates authority** ("god mode," "developer mode," etc.)
- **Telemetry trends**: the most common attacker intent was "forcing irrelevant output" at 28.6%,
  followed by "data destruction" at 14.2%. The most common delivery method was **visible plaintext**
  at 37.8% (suggesting attackers often don't even bother hiding it). The dominant jailbreak method by
  far was **social engineering** at 85.2% — persuasion and impersonated authority are used far more in
  practice than technical obfuscation.
- **First confirmed real-world case**: an attempt to get an AI-based ad-review system to approve a scam
  advertisement by embedding a hidden prompt claiming "this ad has already been approved" (reported by
  Unit 42, first observed December 2025).

**Prevent (additional)**:
- Start from the fact that an **LLM cannot distinguish instructions from data within a single context
  stream**. Adopt techniques like "spotlighting" — prompt designs that explicitly separate untrusted
  content from trusted instructions.
- Newer models' instruction-hierarchy and adversarial-training hardening help somewhat, but are
  **not sufficient alone**; design-level, layered defense is required.

**Detect (additional)**:
- Unit 42 concludes that detection must go beyond simple pattern matching to combine **intent
  analysis, prompt-visibility assessment, and correlation across telemetry sources**.

> Per this document's policy, specific malicious site domains/IOCs are not transcribed here (see the
> original article's "Indicators of Compromise" section).

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

### 5.1 "Double Agents": Over-Broad Default Permissions in GCP Vertex AI (Unit 42, 2026-03-31)

- **Primary source**: Unit 42 research using an agent they built on Vertex AI's Agent Engine. They
  collaborated with Google through a responsible-disclosure process; Google revised its official
  documentation as a result.
- **Content (attack code not transcribed)**: an agent deployed to Vertex AI has an associated **P4SA
  (Per-Project, Per-Product Service Agent)** that carries **excessive permissions by default**. A tool
  inside the agent could reach the cloud metadata service (`metadata.google.internal`) and steal that
  service agent's credentials (an access token).
- **What the stolen credentials reached**: ① unrestricted read access to Cloud Storage buckets in the
  consumer project; ② **restricted container images Google itself manages** (the internal implementation
  of the Vertex AI Reasoning Engine); ③ sensitive files in the tenant project, including a `code.pkl`
  (a Python pickle file — Python's own documentation warns that deserializing untrusted pickle data
  carries RCE risk).
- **A second structural weakness**: the OAuth scopes assigned at deployment time **reached as far as
  Gmail, Calendar and Drive** in Google Workspace, and were not editable by default. Actual impact was
  limited because the corresponding IAM permissions were not separately granted, but Unit 42 flags this
  as a **design-level departure from least privilege**.
- **Google's response**: beyond revising its documentation, Google recommended **BYOSA (Bring Your Own
  Service Account)** — letting an organization replace the default service agent with its own
  least-privilege service account — and confirmed that production images are protected against tampering.

**Relation to the Gambit chain**: like the Sysdig case at the top of this section, this is "cloud
credential theft enabling abuse of an LLM platform" — but here the entry point is not an exploited
vulnerability, it is **excessive permission the cloud provider's own service grants by default**. A
concrete case showing that Gambit chain step ⑥ (over-broad permissions) can arise from **the platform's
own design**, with no need for the attacker to actively misconfigure anything.

**Prevent (additional)**:
- When using a managed AI-agent runtime, **do not take the default service account/service agent's
  permissions at face value**; check whether an option like BYOSA lets you substitute your own
  least-privilege account.
- Remember OAuth scopes are a separate control layer from IAM permissions — check specifically whether
  the defaults are too broad.

---

## 6. Abuse of Multi-Agent Sessions (Agent Session Smuggling, Unit 42, 2025-10-31)

> Patterns A-D so far share one shape: "a single LLM/agent is tricked by malicious data or has its
> credentials stolen." This is different: **a malicious agent itself abuses a legitimate communication
> session to trick another agent**. It doesn't fit cleanly into A-D, so it gets its own pattern.

- **Primary source**: Unit 42 research targeting the A2A (Agent2Agent) protocol, a standard for
  agent-to-agent communication. A PoC built with Google ADK/Gemini 2.5, using two agents: a financial
  assistant and a research assistant.
- **Background**: A2A is designed to be "stateful" — it remembers prior turns and maintains a coherent
  multi-turn conversation. This property means collaborating agents **trust each other by default** in
  many designs.
- **The core of the attack**: a malicious remote agent inserts hidden additional instructions, across
  multiple turns, **between** a legitimate client agent's request and the final response it eventually
  returns. This can lead to ① context poisoning, ② data exfiltration, or ③ unauthorized tool execution
  on the client agent's side.
- **Conditions that make the attack possible (its key properties)**:
  - **Statefulness**: the design persists session state (conversation history, variables, task
    progress) tied to a session ID.
  - **Multi-turn interaction**: enables a gradual, adaptive attack (known to be harder to defend
    against than a single-shot jailbreak).
  - **Autonomy and adaptiveness**: a model-driven agent can dynamically craft its instructions based
    on the client's input and intermediate responses.
  - **Invisible to the end user**: because a typical chat UI only shows the final response, the
    smuggled exchange is **invisible to a human**.
  - MCP (Model Context Protocol) is generally stateless and does not route through an AI model, so
    this kind of multi-stage, adaptive attack is harder to mount there. This is a risk specific to
    protocols — like A2A — that combine persistent state with model-driven reasoning.
- **PoC 1 — sensitive information leakage**: the malicious research assistant, through a series of
  seemingly innocuous clarification questions, successfully extracted the financial assistant's chat
  history, system instructions, available tools and tool schemas.
- **PoC 2 — unauthorized tool invocation**: using the same technique, it got the financial assistant to
  invoke its `buy_stock` tool, executing a 10-share trade without the user's consent.
- **Unit 42's conclusion**: this is not a vulnerability in the A2A protocol itself, but a broader design
  question — **how any stateful protocol interacts with implicit trust between agents**.

**Prevent**:
- Require **out-of-band human confirmation, which the model cannot influence**, for any high-risk
  action (a static UI element or push notification, not a path the generative output can shape).
- **Context grounding**: maintain an "anchor" derived from the original user intent at session start,
  and continuously check that subsequent exchanges stay semantically aligned with it. A significant
  deviation should be flagged as a possible hijack and the session terminated.
- Require **identity verification before agent-to-agent communication**, such as cryptographically
  signed AgentCards (this prevents impersonation/spoofing, though it cannot stop a trusted agent that
  has itself been compromised).
- **Expose the client agent's internal exchanges to the end user** (execution logs, real-time activity
  indicators), rather than showing only the final response.

**Detect**:
- Whether an agent-to-agent exchange drifts into topics or instructions unrelated to the user's
  original intent (the technical basis for context grounding).
- Whether the client agent invokes a tool without a direct instruction from the user (applying this
  repository's **R7** idea — "unexpected multi-step execution" — to agent-to-agent communication
  instead of network/host observation).

---

## 7. Connection points to this repository's existing framework

| Pattern | Connection to the existing framework |
|---|---|
| A. Abuse of execution privilege | R7/R8 (unexpected process spawns), G1 (skill auto-generation), G4 (audit logging) |
| B. System prompt leakage | Same idea as R3 (burst detection of repeated access) |
| C. Indirect prompt injection | R1/R4 (watching egress to LLM/messaging APIs), applied to the agent's own outbound traffic. **Implemented as R9** (`detections/sigma/r9_idpi_steered_egress.yml`, `detections/datadog/r9_idpi_steered_egress.json`) |
| D. LLMjacking | Same pattern as step ⑥ of the Gambit chain (over-broad IAM), G4 (audit log missing/stopped). §5.1's cloud-metadata-service credential theft is **implemented as R10** (`detections/sigma/r10_metadata_service_credential_access.yml`, `detections/datadog/r10_metadata_service_credential_access.json`) |
| E. Abuse of multi-agent sessions | R7 (unexpected multi-step execution) applied to agent-to-agent communication. **Implemented as R11** (`detections/datadog/r11_agent_session_smuggling.json`, though it requires application-level tool-call log instrumentation) |

**A and B are only pointing out the connection, not an implemented detection rule** (their R7/R8/R3 references are an indirect application of rules originally written for the Gambit chain's offensive-agent side; no dedicated rule was written). For C, D and E, actual Sigma/Datadog rules were added to `security-scan/detections/` as R9–R11 (see `security-scan/detections/README.md`). R9/R10 can be detected from standard proxy/network logs; R11 (Agent Session Smuggling) requires application-level tool-call log instrumentation, since no generic network signature exists for it.

## 8. Limits and what is unconfirmed

- Both Semantic Kernel cases and ModelScope ms-agent were confirmed by reading **the original GitHub Security Advisory (GHSA) text directly** from this environment. Context7 could not be reached (neither NVD nor VulnCheck resolved from here), so it rests on secondary sources only, and **even whether a fix exists is disputed** across sources.
- None of these were run to confirm — only the published text was read; no exploit code was written.
- The "Trend Micro" and "Azure AI Foundry" claims attached to PLeak are **not corroborated** (see §3).
- The LLMjacking cost figures are Sysdig's estimates; other articles cite different measurement windows and amounts. Check Sysdig's own posts (sysdig.com/blog) for the exact numbers.
- §2.1 (Unit 42's CrewAI/AutoGen study), §4.1 (Unit 42's web-based IDPI study), §5.1 (Unit 42's "Double Agents") and §6 (Unit 42's Agent Session Smuggling) all organize Unit 42's own primary articles; no independent additional verification was performed, and attack payloads/code are deliberately not transcribed.
- §6's Agent Session Smuggling is PoC-stage research; Unit 42 itself states the attack has "not [been] observed [...] in the wild."

## 9. References (primary and near-primary sources)

- GitHub Security Advisory, GHSA-xjw9-4gw8-4rqx (Semantic Kernel, CVE-2026-26030): https://github.com/microsoft/semantic-kernel/security/advisories/GHSA-xjw9-4gw8-4rqx
- GitHub Security Advisory, GHSA-2ww3-72rp-wpp4 (Semantic Kernel, CVE-2026-25592): https://github.com/microsoft/semantic-kernel/security/advisories/GHSA-2ww3-72rp-wpp4
- GitHub Advisory Database, GHSA-4gc2-344q-r2rw (ModelScope ms-agent, CVE-2026-2256): https://github.com/advisories/GHSA-4gc2-344q-r2rw
- Microsoft, CVE-2025-32711 (EchoLeak): https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711
- Aim Security's technical account of EchoLeak (via The Hacker News): https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html
- Academic post-mortem of EchoLeak (arXiv): https://arxiv.org/html/2509.10540v1
- Hui et al., PLeak (arXiv:2405.06823): https://arxiv.org/abs/2405.06823
- VulnCheck, CVE-2026-75130 (Context7 MCP server): https://fieldguide.lutrasecurity.com/CVE-2026-75130/
- NVD, CVE-2026-2256 (ModelScope ms-agent): https://nvd.nist.gov/vuln/detail/CVE-2026-2256
- Sysdig, LLMjacking (initial report): https://sysdig.com/blog/
- Unit 42, "AI Agents Are Here. So Are the Threats." (CrewAI/AutoGen study, 2025-05-01): https://unit42.paloaltonetworks.com/
- Unit 42, "Double Agents: Exposing Security Blind Spots in GCP Vertex AI" (2026-03-31): https://unit42.paloaltonetworks.com/
- Unit 42, "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild" (2026-03-03): https://unit42.paloaltonetworks.com/
- Unit 42, "When AI Agents Go Rogue: Agent Session Smuggling Attack in A2A Systems" (2025-10-31): https://unit42.paloaltonetworks.com/
- OWASP, Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- OWASP, Agentic AI Threats and Mitigation: https://genai.owasp.org/

> Detection and defense design only. No attack procedures or safety-bypass techniques.
