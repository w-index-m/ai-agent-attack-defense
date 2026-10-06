#!/usr/bin/env python3
"""Summarize semgrep/trivy/gitleaks/zap JSON in a directory. Standard library only.
Usage: summarize.py DIR [--fail-on none|critical|high|medium|low|secret]
Exit 1 if findings at/above the threshold exist."""
import json, os, sys

RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def semgrep(d):
    out = []
    for r in (d or {}).get("results", []):
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(r.get("extra", {}).get("severity", ""), "low")
        out.append(("semgrep", sev, r.get("check_id", ""), f'{r.get("path")}:{r.get("start", {}).get("line")}'))
    return out

def trivy(d):
    out = []
    for res in (d or {}).get("Results", []) or []:
        t = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(("trivy", v.get("Severity", "low").lower(), v.get("VulnerabilityID", ""), f'{t} {v.get("PkgName","")}'))
        for m in res.get("Misconfigurations", []) or []:
            out.append(("trivy", m.get("Severity", "low").lower(), m.get("ID", ""), t))
        for s in res.get("Secrets", []) or []:
            out.append(("trivy-secret", "secret", s.get("RuleID", ""), f'{t}:{s.get("StartLine")}'))
    return out

def gitleaks(d):
    # secret values are never printed
    return [("gitleaks", "secret", r.get("RuleID", ""), f'{r.get("File")}:{r.get("StartLine")}') for r in (d or [])]

def zap(d):
    out = []
    for site in (d or {}).get("site", []):
        for a in site.get("alerts", []):
            sev = {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(str(a.get("riskcode")), "low")
            out.append(("zap", sev, a.get("name", ""), site.get("@name", "")))
    return out

def main():
    args = sys.argv[1:]
    d = args[0] if args else "results"
    fail = "none"
    if "--fail-on" in args:
        fail = args[args.index("--fail-on") + 1]
    items = []
    for name, fn in (("semgrep.json", semgrep), ("trivy.json", trivy), ("gitleaks.json", gitleaks), ("zap.json", zap)):
        p = os.path.join(d, name)
        if os.path.exists(p):
            items += fn(load(p))
    counts = {}
    for _, sev, _, _ in items:
        counts[sev] = counts.get(sev, 0) + 1
    print("## Security scan summary\n")
    print("| severity | count |\n|---|---|")
    for k in ["critical", "high", "medium", "low", "info", "secret"]:
        if counts.get(k):
            print(f"| {k} | {counts[k]} |")
    if not items:
        print("| none | 0 |")
    print("\nTop findings (max 20):")
    top = sorted(items, key=lambda x: -(RANK.get(x[1], 5)))[:20]
    for tool, sev, rid, loc in top:
        print(f"- [{sev}] {tool}: {rid} - {loc}")
    secrets = counts.get("secret", 0)
    if fail == "none":
        bad = False
    elif fail == "secret":
        bad = secrets > 0
    else:
        bad = secrets > 0 or any(RANK.get(sv, 0) >= RANK[fail] for _, sv, _, _ in items if sv != "secret")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
