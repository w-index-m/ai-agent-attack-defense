# ARTEX — Defensive Analysis (primary source, static review)

日本語: [`artex-analysis.ja.md`](artex-analysis.ja.md)

A defensive decomposition of the autonomous AI pentest agent **ARTEX**
([Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)), at the same depth as this repo's
Strix/Cairn/Hermes analysis, mapped to our defensive observation points.

> ⚠️ Scope & policy:
> - **Static review of public source only** — cloned and read; **not built, not run, no deps installed**.
> - **No attack procedures, weaponization, or safety-bypass techniques** are produced or included;
>   skill/exploit contents are not reproduced.
> - ARTEX **actually launches attacks**. Run it **only against assets you own or are authorized to test.**
> - **Supply-chain caution**: external code read statically on an untrusted basis; absence of malicious
>   code is NOT asserted. It ships a self-updater, a MITM proxy, and sends data to external LLMs — so any
>   run belongs in a well-isolated environment and within an authorized scope.

## 1. Overview / provenance

- **Autonomous AI penetration-testing system**, by GitHub user **Autumn-27**. License **AGPL-3.0**.
- Reported **winner** of Baidu BSRC's "Agent+" offense/defense challenge (Chengdu finals, Sep 3, 8 teams).
- Version in the clone: **0.3.15** (screenshot showed 0.3.14). Related projects: asset collection
  [ScopeSentry](https://github.com/Autumn-27/ScopeSentry); approval-UI reference
  [AegisHook](https://github.com/RuoJi6/AegisHook).

## 2. Architecture decomposition (from the repository)

**Stack:** Go backend (in-house agent SDK **`Autumn-27/norma`**) + embedded Next.js frontend as a single
binary, **PostgreSQL** (embedded SQLite also present). JWT auth.

- **Planner / Worker + shared graphs** (`agent/`):
  - **Planner is the sole generator of intents**; **workers execute one intent at a time** and write
    results back — an automated loop (`blackboard_*`, `coldgraph`, `compaction`, `constraints`).
  - **Dual graph**: a cross-task shared **asset graph** and a per-task **exploration graph**.
- **Recording proxy** (`traffic/`, via `lqqyt2423/go-mitmproxy`): all traffic is recorded through a MITM
  proxy and searchable by the agent. **= a single egress chokepoint.**
- **LLM layer**: `llmpool` (provider pool + health policy), `llmrec` (**records LLM calls**).
  Supports **Anthropic / OpenAI + compatible**; provider/model/endpoint set in the UI.
- **MCP client** (`mcphttp/`, SSE / Streamable HTTP) — the external-tool extension point.
- **Skill mechanism** (`skills/`, file-based `SKILL.md` = Hermes-style). Bundled packs are recon/scope
  oriented — **api-recon / playwright-cli (browser automation) / scopesentry** (contents not reproduced here).
- **Recon libraries**: ProjectDiscovery (`dnsx` / `cdncheck` / `blackrock`), `miekg/dns`.
- **Built-in governance (notable)**: `guard/` (**approval gate: allow/deny/confirm**), `intercept/`
  (**deny rules for destructive endpoints** — e.g. `/delete /del /remove /unlink /erase /destroy` blocked by
  default; plus model-based fallback review), scope enforcement (`assets_scope` / `asset_intercept` /
  `intercept_filter` / `orchestration`), `evidence/` (evidence store), `selfupdate/` (auto-update).

## 3. Compared to Strix / Cairn / Hermes

- **Architecturally closest to Cairn**: planner/worker + shared intent/asset graphs (≈ Cairn's
  blackboard / fact-intent graph).
- Also carries a **Hermes-style skill mechanism** (file-based `SKILL.md` extensions).
- Has **platform/MCP** traits (type ⑤ in §6) that bundle external tools → a **hybrid**.
- **Standout difference = heavy built-in governance**: the tool itself enforces an approval gate,
  destructive-op deny rules, scope limits, and LLM-call recording — more "governed" than the other three.

## 4. Defensive observation points → R1–R7 / G1–G6

| ARTEX component / behavior | Observation point | This repo's detection |
|---|---|---|
| LLM calls (Anthropic/OpenAI/compat, `llmpool`/`llmrec`) | LLM egress from servers | **R1** (local LLM → shifts to R7) |
| Workers' rapid multi-tool execution, `norma`, MCP | Many tool types under one process | **R7** |
| Kali/tools, Docker execution | Privileged / container spawn | **R2** |
| Recon skills, ProjectDiscovery, DNS enumeration | Recon burst | **R3** (+ web 4xx aggregation) |
| Recording MITM proxy (`traffic/`) | Single path for all traffic | chokepoint where **R1/R4 (egress) · R3** are easy to see |
| Messaging / external notify (`notify/`) | C2-like channel | **R4** |
| Skill mechanism (`SKILL.md`) used to bypass safety | Governance signal | **T1562-equivalent · G1–G6** |
| **ARTEX's own approval / intercept / scope / LLM-record** | Audit points under authorized use | **G1–G6** (approval, audit, privilege, logging) |

**Takeaway**: the recording proxy and the single planner are efficiency wins for the attacker, but for the
defender they are **concentrated observation points / pressure points**. ARTEX's own approval gate, deny
rules, scope enforcement and LLM recording are also a template for what an org that **runs an attack agent
under authorization** should capture under **G1–G6**.

## 5. Unverified claims (do not take as fact)

- Reports of **ARTEX traces in a Korean financial-sector breach** (Shinhan Bank-related; the string
  `ARTEX-自主渗透测试控制台` in a web server's HTML title; DeepSeek integration) → **suspicion/clue, not confirmed**.
- Chinese-community claims of a **"0-day found with zero human intervention"** (Kingdee) → **unverified**.

## 6. Sources

- Upstream repo (AGPL-3.0): https://github.com/Autumn-27/ARTEX (static review) · English-UI fork:
  https://github.com/hongvincent/ARTEX
- Write-up (JP): https://piyolog.hatenadiary.jp/ — "ARTEX とは"
- Write-up (EN): https://zendot.org/en/posts/autumn-27-artex
- Reporting (unconfirmed): SBS / Seoul Economic Daily / BigGo (Korea, financial sector)

> Detection/defense design only. No attack execution or safety-bypass techniques.
