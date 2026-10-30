#!/usr/bin/env python3
"""診断結果(Semgrep / Trivy / gitleaks / ZAP / 依存関係の照合(SARIF)の JSON)を集計して出力する。

出力形式(--format):
  markdown  CI の要約(既定)。ジョブサマリに貼れる Markdown。
  elastic   Elastic/ECS 向けの NDJSON(1 行 1 イベント)。Elastic に取り込める。
  datadog   Datadog Logs 向けの JSON 配列。Datadog に取り込める。
            → CI のスキャン結果を、検知ルール(R1–R8)が載る SIEM 側へ流すための出力。

使い方:
  python3 scripts/summarize.py results                        # 要約だけ(失敗させない)
  python3 scripts/summarize.py results --fail-on high         # high 以上があれば終了コード 1
  python3 scripts/summarize.py results --format elastic --out scan.ndjson
  python3 scripts/summarize.py results --format datadog --out scan.json
  --fail-on は none / critical / high / medium / low / secret のいずれか
    secret: 秘密情報が 1 件でもあれば失敗
標準ライブラリだけで動く。ネットワークへは送らない(ファイル/標準出力に書くだけ)。
"""
import argparse, json, os, sys, time
from datetime import datetime, timezone

ORDER = ["critical", "high", "medium", "low", "info"]
LABEL = {"critical": "緊急", "high": "高", "medium": "中", "low": "低", "info": "情報"}
# 重大度 → 数値(大きいほど深刻。ECS の event.severity 用)
SEV_NUM = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# 重大度 → Datadog のログ status
DD_STATUS = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}


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


def sqli_lab(data):
    # security-scan/sqli-lab/run_regression.py の出力。ここに現れるのは
    # 「このリポジトリの脆弱性」ではなく、このラボ自身の検出スクリプトの
    # リグレッション(本来VULNERABLEのはずがsafe判定になった等)。
    # 詳細は security-scan/sqli-lab/README.ja.md の TODO セクション参照。
    for r in data or []:
        yield ("sqli_lab", r.get("severity", "high"), r.get("title", ""), r.get("location", ""), False)


def hackingbuddygpt_regression(data):
    # security-scan/hackingbuddygpt-local-poc/run_regression.py の出力。ここに現れるのは
    # 「このリポジトリの脆弱性」でも「hackingBuddyGPTの脆弱性」でもなく、本リポジトリが
    # 記録した外部プロジェクト(hackingBuddyGPT)のバグ(api_baseが死んでいる設定項目)に
    # 関するドキュメントが、upstream側の変化で古くなっていないかのカナリア。
    # 詳細は security-scan/hackingbuddygpt-local-backend-notes.md 参照。
    for r in data or []:
        yield ("hackingbuddygpt_regression", r.get("severity", "medium"), r.get("title", ""), r.get("location", ""), False)


def dep_cve(data):
    # scripts/dep_cve_check.py の出力(SARIF 2.1.0)。OSV.dev に照合した、依存関係の既知の脆弱性。
    # SARIF の level → 重大度: error→high / warning→medium / note→low。
    # dep_cve_check は CRITICAL と HIGH を区別せず error にまとめるため、critical にはならない。
    # ruleId が "dep_cve_check/error" のものは、脆弱性ではなく「OSV に確認できなかった」
    # という報告。「脆弱性なし」と取り違えないよう、重大度は info にし、要約で別に数える。
    m = {"error": "high", "warning": "medium", "note": "low"}
    for run in (data or {}).get("runs", []):
        for r in run.get("results", []):
            loc = ""
            locs = r.get("locations") or []
            if locs:
                loc = locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            text = (r.get("message") or {}).get("text", "")
            if r.get("ruleId") == "dep_cve_check/error":
                yield ("dep_cve", "info", text, loc, False)
                continue
            title = (r.get("properties") or {}).get("title") or r.get("ruleId", "")
            yield ("dep_cve", m.get(r.get("level", ""), "medium"), "%s — %s" % (title, text), loc, False)


SOURCES = [
    ("semgrep.json", semgrep),
    ("trivy.json", trivy),
    ("gitleaks.json", gitleaks),
    ("zap.json", zap),
    ("sqli_lab.json", sqli_lab),
    ("hackingbuddygpt_regression.json", hackingbuddygpt_regression),
    ("dep_cve.json", dep_cve),
]


def norm_sev(sev):
    return sev if sev in ORDER else "info"


def render_markdown(found, items):
    counts = {s: 0 for s in ORDER}
    for _, sev, _, _, _ in items:
        counts[norm_sev(sev)] += 1
    secrets = sum(1 for i in items if i[4])
    out = ["## 診断の要約", "", "対象ファイル: %s" % (", ".join(found) or "なし"), "",
           "| 重大度 | 件数 |", "|---|---|"]
    for s in ORDER:
        out.append("| %s | %d |" % (LABEL[s], counts[s]))
    out += ["", "秘密情報の検出: %d 件" % secrets, ""]
    unchecked = sum(1 for i in items if i[0] == "dep_cve" and i[1] == "info")
    if unchecked:
        out += ["⚠️ 依存関係の照合で、OSV に確認できなかったものが %d 件あります(「情報」の件数に含まれます。「脆弱性なし」ではありません)。" % unchecked, ""]
    top = [i for i in items if norm_sev(i[1]) in ("critical", "high")][:10]
    if top:
        out.append("### 緊急・高の指摘(先頭 %d 件)" % len(top))
        for tool, sev, title, loc, _ in top:
            out.append("- [%s] %s: %s (%s)" % (LABEL.get(norm_sev(sev), sev), tool, title, loc))
        out.append("")
    out.append("全件を見るには、保存された JSON を「脆弱性トリアージ」ページに読み込んでください。")
    return "\n".join(out)


def render_elastic(found, items):
    """ECS 風の NDJSON(1 行 1 イベント)。dotted フィールドは Elastic が解釈できる。"""
    ts = datetime.now(timezone.utc).isoformat()
    lines = []
    for tool, sev, title, loc, is_secret in items:
        s = norm_sev(sev)
        ev = {
            "@timestamp": ts,
            "event.kind": "alert",
            "event.category": ["vulnerability"],
            "event.module": "security-scan",
            "event.dataset": "security-scan.%s" % tool,
            "event.severity": SEV_NUM[s],
            "observer.name": "summarize.py",
            "vulnerability.severity": s,
            "rule.name": title,
            "file.path": loc,
            "labels": {"secret": bool(is_secret), "tool": tool},
            "message": "[%s] %s: %s (%s)" % (s, tool, title, loc),
        }
        lines.append(json.dumps(ev, ensure_ascii=False))
    return "\n".join(lines)


def render_datadog(found, items):
    """Datadog Logs 取り込み用の JSON 配列。"""
    ms = int(time.time() * 1000)
    events = []
    for tool, sev, title, loc, is_secret in items:
        s = norm_sev(sev)
        events.append({
            "ddsource": "security-scan",
            "service": "ci-scan",
            "ddtags": "tool:%s,severity:%s,secret:%s" % (tool, s, str(bool(is_secret)).lower()),
            "status": DD_STATUS[s],
            "timestamp": ms,
            "tool": tool,
            "severity": s,
            "title": title,
            "location": loc,
            "secret": bool(is_secret),
            "message": "[%s] %s: %s (%s)" % (s, tool, title, loc),
        })
    return json.dumps(events, ensure_ascii=False, indent=2)


RENDERERS = {"markdown": render_markdown, "elastic": render_elastic, "datadog": render_datadog}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--fail-on", default="none")
    ap.add_argument("--top", type=int, default=10)  # 後方互換(markdown は先頭 10 件固定)
    ap.add_argument("--format", default="markdown", choices=list(RENDERERS))
    ap.add_argument("--out", default="", help="出力先ファイル(既定: 標準出力)")
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

    text = RENDERERS[a.format](found, items)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + ("\n" if text and not text.endswith("\n") else ""))
        print("%s を書き出しました(%d 件, 形式: %s)" % (a.out, len(items), a.format), file=sys.stderr)
    else:
        print(text)

    counts = {s: 0 for s in ORDER}
    for _, sev, _, _, _ in items:
        counts[norm_sev(sev)] += 1
    secrets = sum(1 for i in items if i[4])

    fail = False
    if a.fail_on == "secret":
        fail = secrets > 0
    elif a.fail_on in ORDER:
        idx = ORDER.index(a.fail_on)
        fail = any(counts[s] for s in ORDER[: idx + 1])
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
