# Cross-tool defense & detection notes (Strix / Cairn / Hermes) — English

English mirror of `defense-detection-notes.md`. Framed for defenders: observation
points and controls, **detection content only** — no attack recipes, no safety-bypass
techniques.

Sources: [Gambit Security](https://gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company) /
[Strix](https://github.com/usestrix/strix) / [Cairn](https://github.com/oritera/Cairn) / [Hermes](https://github.com/NousResearch/hermes-agent)

## Roles in the attack chain

| Stage | Tool | Role | Technical traits |
|---|---|---|---|
| Recon / scan | **Strix** | Attack-surface discovery, vuln hunting | Runs in a Docker sandbox, Caido proxy for HTTP capture, bundles nmap/ffuf/playwright |
| Exploratory intrusion | **Cairn** | Self-directed search to a goal (shell/flag) | Blackboard server (:8000) + fact-intent graph, OODA workers in per-project containers (NET_RAW/NET_ADMIN) |
| Orchestration / post | **Hermes** | Campaign orchestration & post-access | General agent, many skills, Telegram/Discord/Slack gateways, cron, subagents, 7 execution backends |

Common substrate: **continuous egress to an LLM API** (OpenRouter/Claude/DeepSeek in the
report). This is the most stable shared observation point across all three.

## Per-stage signals → defense/detection

### A. Recon/scan (Strix-like)
Signals: broad port/path scanning from one source, request bursts, known scanner
fingerprints, automated-browser (CDP/playwright) fingerprints, periodic/bursty LLM-API
HTTPS egress.
Defense: WAF/rate-limit, scan detection (many 404/403, path enumeration), bot defense;
authenticate + IP-restrict admin/sensitive endpoints; security headers (CSP/HSTS/XFO/nosniff);
**CSP on payment pages is key against skimmer injection**.

### B. Exploratory intrusion (Cairn-like)
Signals: a blackboard server (:8000, FastAPI) + many per-project worker containers
(`cairn-worker-container`, with NET_RAW/NET_ADMIN); repeated try→observe→retry (OODA);
continuous LLM egress plus intermittent probing of the target.
Defense: EDR/container-runtime monitoring (privileged-cap container starts, unknown image
pulls, host-network mode); internal segmentation; least privilege + MFA on key assets;
egress domain allowlist.

### C. Orchestration/post (Hermes-like)
Signals: outbound to messaging apps (Telegram/Discord/Slack/Signal) = possible C2;
persistence via cron/scheduler; mass subagent spawn; dynamic skill creation/self-modification;
"remove my own safety filter"-type skills (Gambit: 78/121 attack skills incl. filter removal).
Defense: monitor outbound messaging APIs (strong anomaly from server hosts); persistence
monitoring; process-tree anomalies; LLM-use governance (detect attempts to remove/bypass
safety mechanisms).

## Cross-cutting controls (by priority)

1. **Egress allowlist** — block/monitor LLM/messaging egress from server zones by default.
2. **Container/runtime visibility** — detect privileged caps, host-net, unknown/unsigned images.
3. **Attack-surface minimization** — isolate admin UIs, don't expose DBs/services directly.
4. **CSP on payment/sensitive pages** — prevent skimmer/card-stealing injection.
5. **Persistence/automation monitoring** — cron/schedules, rapid automated tool runs, subagent fan-out.
6. **Log correlation** — recon + LLM egress + privileged containers + outbound messaging, correlated over time, reveals the autonomous-agent attack that single signals miss.

---

# Operational layer (SOC / detection engineering)

Data source → signal → detection logic. Rule sketches are vendor-neutral Sigma-style
pseudo-notation (defensive detections, not attack steps). Tune thresholds to your baseline.

## 1. Data-source map

| Data source | Stage | Main signals |
|---|---|---|
| Proxy / NetFlow / DNS | all (top) | egress to LLM / messaging APIs |
| Container audit (Docker events / containerd / Falco / auditd) | intrusion / tooling | privileged cap / host net / unknown image |
| EDR / process telemetry (Sysmon / auditd / eBPF) | intrusion / orchestration | scanner processes, subagent fan-out, rapid tool runs |
| Web / WAF logs | recon | path enumeration, 4xx bursts, admin probes |
| Host persistence (cron / systemd / autostart) | orchestration | new schedules/services |
| Auth / audit logs | intrusion / post | abnormal privilege gain, lateral movement |

## 2. Detection rule sketches

- **R1** — Server-zone host → external LLM API (proxy/DNS/NetFlow; allowlist approved LLM use). High.
- **R2** — Container start with NET_RAW/NET_ADMIN, privileged, or host network (container audit). Med.
- **R3** — Admin/sensitive path enumeration with 4xx burst from one source (web/WAF). Med.
- **R4** — Server-zone host → messaging API (Telegram/Discord/Slack/Signal). High.
- **R5** — New cron/systemd persistence (host file events). Med.
- **R6** — Correlation: R3 AND R1 AND (R2 OR R7) [+ optional R4/R5] within a window → escalate as autonomous-AI-agent attack. High.
- **R7** — One parent process spawning many distinct security tools in a short window
  (EDR). **Persists even when the agent uses a local LLM and shows no LLM egress (R1).**
  Also catches MCP frameworks orchestrating 150+ tools (HexStrike-like). High.

Runnable rule files: `detections/` (Sigma, Falco, Datadog).

## 3. MITRE ATT&CK mapping

| Stage | Technique | Detection |
|---|---|---|
| Recon | T1595 / T1046 | R3 |
| Execution/tooling | T1059 | EDR rapid runs, R2, R7 |
| C2 | T1071 (messaging abuse) | R4 |
| Persistence | T1053 (cron/timer) | R5 |
| Defense evasion | T1562 Impair Defenses (safety-mechanism removal) | governance detection (below) |
| Discovery / lateral | T1046 / auth anomalies | R2, auth logs |
| Exfiltration | T1041 over C2 | R1/R4 + DLP correlation |

T1562-equivalent (e.g. Hermes removing its own safety filter) is hard to catch with simple
network/host signals; cover it with LLM-use governance (audit of prompts/tool calls, detection
of attempts to remove/bypass safety). This note only flags the existence of the signal; it does
not cover bypass techniques.

## 4. SOC triage (by priority)

1. **R1/R4 hit** → confirm the host's business purpose; if not approved, contain (block egress) + inspect processes/containers.
2. **R2 hit** → check origin, image provenance, cap necessity. Unknown image + privileged = high confidence.
3. **R3 hit** → check the asset's exposure (admin UI, risky ports) with `netcheck` etc. and close it.
4. **R5 hit** → remove persistence, trace the creating process lineage.
5. **R6 (correlation)** → treat as a chain beyond single signals; open an incident / full IR.

## 5. Prevention (fixed controls ahead of detection)

- Egress **allowlist** (default-block LLM/messaging from server zones).
- Container admission control: forbid privileged caps / host net / unsigned/unknown images.
- Attack-surface minimization: isolate admin UIs; don't expose DBs/services directly (`netcheck` risky ports).
- **CSP** on payment/sensitive pages (skimmer/card-theft injection prevention).
- LLM-use audit & governance (detect/report attempts to remove or bypass safety mechanisms).

---

# 6. Broader offensive-AI-agent landscape & defense mapping

The Gambit trio is one instance of the "division-of-labor chain" type. The good news:
**as the catalog grows, the observable fundamentals stay shared** (LLM inference, scanning,
tool execution, optional C2), so R1–R7 generalize — no need to rebuild per tool.

## 6.1 Type map (defensive view)

| Type | Examples | Nature | Detections that apply |
|---|---|---|---|
| ① Division-of-labor chain | Hermes+Strix+Cairn | split roles (orchestrate/recon/intrude) | R1 R3 R2 R4 R5 R7 + correlation R6 |
| ④ End-to-end autonomous pentest | PentAGI, Villager, PentestAgent, Pentest-Swarm, hackingBuddyGPT, … | recon→exec→verify in one tool (often multi-agent, Kali container) | R7 R2 R3 (+ R1 unless local LLM) |
| ⑤ Attack framework | HexStrike AI, CAI, TARS | a base that arms agents with many tools (MCP, 150+ tools) | R7 (rapid multi-tool) R2 R3 |
| ⑥ Interactive assistant | PentestGPT, Pentest Copilot | human-led, AI assists (some have autonomous modes) | R3 R7 (when autonomous); human-paced, relatively slower |

Type taxonomy follows a public summary by 三輪信雄 (@NobMiwa). Classifications/capabilities
shift; treat them behaviorally, not as fixed.

## 6.2 Detection emphasis for newer types

- **Local-LLM variants (PentAGI/Ollama, Villager/DeepSeek-local) evade R1 (LLM egress).**
  → shift weight to **R7 (rapid multi-tool execution) and R2 (Kali/containers)**.
- **Framework types (HexStrike) orchestrate many tools via MCP** → catch the concentration of
  distinct tool child-processes under one parent with R7.
- **E2E types run inside Kali-based containers** → R2 for unknown/Kali image + privileged, R7 for
  the internal multi-tool runs, R6 to correlate.
- Across all types, the fixed controls in §5 (egress allowlist, container admission control,
  attack-surface minimization) act ahead of detection.

## 6.3 Tools with reported/suspected abuse (advisory)

- **Villager** (Cyberspike; Kali + DeepSeek; 10k+ PyPI downloads): tied to abandoned AsyncRAT
  distribution infra; feared to follow the "next Cobalt Strike" path.
- **HexStrike AI** (OSS; MCP orchestrating 150+ tools): reportedly used to exploit Citrix
  CVE-2025-7775 et al. within minutes, per forum chatter.
- **ARTEX AI / Villager**: real-attack abuse reported/suspected (per the @NobMiwa summary).

This is awareness only. These notes stay on detection/defense and do not cover acquiring,
running, or abusing any tool.

## 6.4 Summary

The attacker "catalog" keeps growing, but **defense generalizes behaviorally**. This repo's
detections (`detections/` R1–R7 + correlation R6) and prevention (§5) extend beyond the Gambit
trio to much of types ④⑤⑥. Priority: **R1/R4 (egress) → R2 (privileged container) → R7
(rapid multi-tool) → R3 (recon) → R5 (persistence) → R6 (correlation)**.

> Detection/defense design only. No attack execution or safety-bypass steps.
