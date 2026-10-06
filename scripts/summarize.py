#!/usr/bin/env python3
"""診断結果(Semgrep / Trivy / gitleaks / ZAP の JSON)を集計して、Markdown の要約を出す。

使い方:
  python3 scripts/summarize.py results                 # 要約だけ(失敗させない)
  python3 scripts/summarize.py results --fail-on high  # high 以上があれば終了コード 1
  --fail-on は none / critical / high / medium / low / secret のいずれか
    secret: 秘密情報が 1 件でもあれば失敗
標準ライブラリだけで動く。
"""
import argparse, json, os, sys

ORDER = ["critical", "high", "medium", "low", "info"]
LABEL = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def semgrep(data):
    m = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for r in (data or {}).get("results", []):
        e = r.get("extra", {})
        yield ("semgrep", m.get(str(e.get("severity", "")).upper(), "info"),
               r.get("check_id", ""), "%s:%s" % (r.get("path", ""), r.get("start", {}).get("line", "")), False)


def trivy(data):
    for res in (data or {}).get("Results", []):
        t = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            yield ("trivy", v.get("Severity", "info").lower(), "%s %s" % (v.get("VulnerabilityID", ""), v.get("PkgName", "")), t, False)
        for x in res.get("Misconfigurations") or []:
            yield ("trivy", x.get("Severity", "info").lower(), x.get("Title", x.get("ID", "")), t, False)
        for x in res.get("Secrets") or []:
            yield ("trivy", x.get("Severity", "high").lower(), x.get("Title", "secret"), t, True)


def gitleaks(data):
    for r in data or []:
        yield ("gitleaks", "high", r.get("Description") or r.get("RuleID", "secret"),
               "%s:%s" % (r.get("File", ""), r.get("StartLine", "")), True)


def zap(data):
    m = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for site in (data or {}).get("site", []):
        for a in site.get("alerts", []):
            yield ("zap", m.get(str(a.get("riskcode", "0")), "info"), a.get("name", ""), site.get("@name", ""), False)


SOURCES = [("semgrep.json", semgrep), ("trivy.json", trivy), ("gitleaks.json", gitleaks), ("zap.json", zap)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--fail-on", default="none")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()

    items, found = [], []
    for name, fn in SOURCES:
        p = os.path.join(a.dir, name)
        if not os.path.exists(p):
            continue
        data = load(p)
        if data is None:
            print("読めなかったファイル: %s" % name, file=sys.stderr)
            continue
        found.append(name)
        items.extend(fn(data))

    counts = {s: 0 for s in ORDER}
    for _, sev, _, _, _ in items:
        counts[sev if sev in counts else "info"] += 1
    secrets = sum(1 for i in items if i[4])

    print("## 診断の要約")
    print("")
    print("対象ファイル: %s" % (", ".join(found) or "なし"))
    print("")
    print("| 重大度 | 件数 |")
    print("|---|---|")
    for s in ORDER:
        print("| %s | %d |" % (LABEL[s], counts[s]))
    print("")
    print("秘密情報の検出: %d 件" % secrets)
    print("")
    top = [i for i in items if i[1] in ("critical", "high")][: a.top]
    if top:
        print("### 緊急・高の指摘(先頭 %d 件)" % len(top))
        for tool, sev, title, loc, _ in top:
            print("- [%s] %s: %s (%s)" % (LABEL.get(sev, sev), tool, title, loc))
        print("")
    print("全件を見るには、保存された JSON を「脆弱性トリアージ」ページに読み込んでください。")

    fail = False
    if a.fail_on == "secret":
        fail = secrets > 0
    elif a.fail_on in ORDER:
        idx = ORDER.index(a.fail_on)
        fail = any(counts[s] for s in ORDER[: idx + 1])
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
