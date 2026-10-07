# Sandbox defense model — by scan pattern (English)

日本語版: [`sandbox-defense-model.ja.md`](sandbox-defense-model.ja.md)

A defensive, educational walkthrough of what happens, by design, if you run various
scans against an ephemeral, least-privilege, egress-restricted execution platform
(e.g. a Claude Code cloud sandbox). Detection/defense framing only — no attack
execution steps, no safety-bypass techniques.

> ⚠️ Authorization boundary: vulnerability scanning or penetration testing of the
> operating platform itself (infrastructure someone else runs) is NOT authorized just
> because you are a user of it. Run real scans only against assets you own or are
> authorized to test. To test an operator's systems (e.g. Anthropic's), follow their
> responsible-disclosure / bug-bounty program's defined scope and rules of engagement.
> This note involves no real scanning.

## Per-pattern: goal / how a hardened platform absorbs it / mapped detection

| # | Pattern | Scan goal | How a hardened platform absorbs it | Mapped detection |
|---|---|---|---|---|
| ① | Port/service (nmap-like) | enumerate open ports, services, banners, old versions | no services exposed to the user; egress only via proxy allowlist; raw-socket scans have no capability | R3 (recon enumeration) |
| ② | Web vuln (ZAP/nuclei-like) | auth, input handling, headers/CSP, known CVEs | nothing to hit unless YOU stand up a web app; meaningful only against your own staging | R3, web 4xx aggregation |
| ③ | Container / privesc / escape | privileged, dangerous caps, host net, kernel flaws to break out to the host | privilege separation, minimal caps, ephemeral; privileged/NET_RAW absent by default, no foothold persists | R2 (privileged container), G5 (privilege expansion) |
| ④ | Internal net / lateral / metadata | sweep internal ranges, steal creds from 169.254.x | egress limited to allowlist; internal/metadata/link-local blocked; no adjacent host to move to | R1/R4 (unexpected egress), R6 (correlation) |
| ⑤ | Secrets / deps / code (gitleaks/Trivy/Semgrep) | hardcoded keys, vulnerable deps, risky code | targets CODE, not the platform → can be run legitimately against your own repo | pre-emptive CI gate + triage |
| ⑥ | Persistence / C2 behavior | cron/service persistence, outbound command channel | ephemeral makes persistence moot; egress allowlist-limited | R5 (persistence), R4 (C2), G1–G6 |

## What "ephemeral" really means — re-instantiate ≠ re-implement

It is true the sandbox is **re-instantiated** on each launch — but it is not
**re-implemented** (code rewritten). Each launch builds a **fresh instance from a fixed
recipe** (a base image + the environment's setup script/config).

- **Fresh each launch**: the container is disposable; the repo is cloned fresh; it is
  reclaimed on end/inactivity, and no prior state carries over.
- **Same each launch**: the foundation is a fixed image/config — contents don't change
  randomly; the same configuration is reproduced.

### Security implications
- **What ephemerality protects: persistence / foothold.** Anything planted is gone at
  session end — persistence (R5), standing C2 (⑥) and lateral footholds don't survive.
  Staying resident is structurally hard.
- **What ephemerality does NOT protect: the attack surface itself.** The same image each
  time means the same attack surface each time. A weakness isn't erased by "rebuilding";
  it exists identically every launch. Fixing it requires updating the image/config
  (a patch) — a restart does not roll it away.

> Bottom line: "new every time" ≠ "safe every time." **Ephemerality prevents squatting,
> but whether a weakness exists is decided by how the foundation is built
> (least privilege, isolation, egress allowlist, patching).**

## The shared principle of "why it doesn't land" (structural containment)

1. **Minimal exposure** (no public services) → ①② miss
2. **Privilege separation / minimal caps** (no privileged/NET_RAW) → ③ rarely lands
3. **Egress allowlist + internal/metadata blocking** → ④ can't reach
4. **Ephemeral (disposable)** → no foothold for ③⑥
5. **Fixed resource budget** → abuse impact localized

These five are the inverse of detections R1–R7 / G1–G6. For each pattern an attacker
targets, the platform answers with structural containment and the SOC answers with
detection of the deviation — attack and defense share the same observation points.

> Detection/defense design only. No attack execution or safety-bypass steps.
