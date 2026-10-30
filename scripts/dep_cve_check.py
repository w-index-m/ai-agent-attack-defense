#!/usr/bin/env python3
"""依存関係の既知脆弱性の確認（OSV.dev への照合）。

requirements.txt（pip、`==` で固定された行のみ）と、npm の package-lock.json
（lockfileVersion 1/2/3 に対応）を読み、各パッケージの正確なバージョンを、
公開の脆弱性データベース OSV（https://osv.dev）に照合する。

確認専用：
- 自分の環境が「既知の脆弱性に該当する版を使っていないか」を見るだけ。
- 攻撃・悪用は行わない。OSV への問い合わせは、パッケージ名とバージョンを渡す
  読み取り専用の API 呼び出し。

依存は標準ライブラリのみ（urllib.request）。

使い方:
    python3 scripts/dep_cve_check.py --requirements requirements.txt --out dep_cve.sarif
    python3 scripts/dep_cve_check.py --npm-lock package-lock.json --out dep_cve.sarif
    python3 scripts/dep_cve_check.py --requirements requirements.txt --npm-lock package-lock.json

検証状況: OSV API（api.osv.dev）への実通信は、Windows の PC（一般的なインターネット
接続）で確認済み（2026-10-30。jinja2==2.10 / requests==2.19.0 で 22件を検出、
確認できなかった 0件）。パース処理と SARIF 生成はローカルのモックサーバーでも検証済み
（詳細: security-scan/dep-cve-check-notes.md）。

終了コード: 0=脆弱性なし・全件確認済み / 1=既知の脆弱性あり / 2=確認できなかった
パッケージがある（脆弱性なしとは言えない）。
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
TIMEOUT = 10.0


def parse_requirements(path):
    """requirements.txt を読み、`==` で正確に固定された行だけを (name, version) で返す。
    範囲指定（>=, ~=, >, < など）や git/url 由来の行は、正確な版が分からないため
    スキップし、その旨を stderr に出す。"""
    out = []
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http://", "https://")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([0-9][A-Za-z0-9_.\-]*)\s*$", line)
            if m:
                out.append((m.group(1), m.group(3)))
                continue
            m2 = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<)", line)
            name = m2.group(1) if m2 else line
            print("requirements.txt:%d: 正確な版が分からないためスキップ: %s" % (lineno, line), file=sys.stderr)
    return out


def parse_npm_lock(path):
    """npm の package-lock.json を読み、(name, version) の一覧を返す。
    lockfileVersion 2/3 の "packages" 形式と、1 の入れ子の "dependencies" 形式の
    両方に対応する。"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, info in packages.items():
            if not key or not isinstance(info, dict):
                continue
            version = info.get("version")
            if not version:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            out.append((name, version))
        return out

    def walk(deps):
        for name, info in (deps or {}).items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if version:
                out.append((name, version))
            walk(info.get("dependencies"))

    walk(data.get("dependencies"))
    return out


def osv_query(name, version, ecosystem, timeout=TIMEOUT):
    """OSV の /v1/query に1件問い合わせる。読み取り専用。失敗時は例外を投げる
    （「脆弱性なし」と「確認できなかった」を混同しないため、黙って空にはしない）。"""
    body = json.dumps({"version": version, "package": {"name": name, "ecosystem": ecosystem}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def severity_level(vuln):
    """OSV の database_specific.severity（GHSA 由来のエントリに多い）があれば使う。
    無ければ "warning" を既定値にする（過小評価より過大評価を選ぶ）。"""
    sev = (vuln.get("database_specific") or {}).get("severity", "")
    sev = str(sev).upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev in ("MODERATE", "MEDIUM"):
        return "warning"
    if sev == "LOW":
        return "note"
    return "warning"


_LEVEL_RANK = {"note": 0, "warning": 1, "error": 2}


def merge_by_cve(findings):
    """同じパッケージ・同じ CVE が、別のデータベースのエントリ（GHSA と PYSEC など）
    として複数返ることがある。CVE 番号（無ければ OSV ID）ごとに1件にまとめる。
    - 重大度: 明示された値（database_specific.severity）があるものを優先し、
      複数あれば高いほうを採る。どれも明示が無ければ既定値のまま。
    - 修正版: 和集合。
    - 要約: 空でない最初のもの（OSV ID そのままの要約は避ける）。"""
    merged = {}
    for f in findings:
        key = (f["manifest"], f["name"], f["version"], f["cve"] or f["osv_id"])
        m = merged.get(key)
        if m is None:
            merged[key] = dict(f, osv_ids=[f["osv_id"]], fixed=list(f["fixed"]))
            continue
        m["osv_ids"].append(f["osv_id"])
        if f["explicit"] and (not m["explicit"] or _LEVEL_RANK[f["level"]] > _LEVEL_RANK[m["level"]]):
            m["level"], m["explicit"] = f["level"], True
        for v in f["fixed"]:
            if v not in m["fixed"]:
                m["fixed"].append(v)
        if not m["summary"] and f["summary"]:
            m["summary"] = f["summary"]
    return list(merged.values())


def fixed_versions_for(vuln, name, ecosystem):
    """この (name, ecosystem) に対応する affected エントリから、
    "fixed" イベントのバージョンを集めて返す。"""
    fixed = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name") != name or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
    # 重複を除き、順序を保つ
    seen = set()
    uniq = []
    for v in fixed:
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def cve_alias(vuln):
    for a in vuln.get("aliases", []) or []:
        if a.startswith("CVE-"):
            return a
    return None


_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _fmt_fixed(v):
    """PYSEC 由来のレコードは、"fixed" にバージョン番号でなく git のコミットハッシュを
    入れることがある。バージョンと取り違えないよう、短縮してコミットと明示する。"""
    return "コミット %s" % v[:7] if _COMMIT_SHA.match(v) else v


def to_sarif(findings, errors):
    """vuln_triage.html がそのまま読み込める SARIF 2.1.0 を作る
    （taxonomy.json の triage_scanners に "sarif" が既にあるため、新しい取り込み
    処理は不要）。"""
    results = []
    for f in findings:
        rule_id = f["cve"] or f["osv_id"]
        title = "%s %s %s" % (f["name"], f["version"], rule_id)
        msg = f["summary"] or f["osv_id"]
        if len(f.get("osv_ids", [])) > 1:
            msg += "（OSV: %s）" % ", ".join(f["osv_ids"])
        if f["fixed"]:
            msg += "（修正版: %s）" % ", ".join(_fmt_fixed(v) for v in f["fixed"])
        results.append({
            "ruleId": rule_id,
            "level": f["level"],
            "message": {"text": msg},
            "properties": {"title": title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["manifest"]},
                }
            }],
        })
    for e in errors:
        results.append({
            "ruleId": "dep_cve_check/error",
            "level": "note",
            "message": {"text": "確認できなかった: %s %s — %s" % (e["name"], e["version"], e["reason"])},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": e["manifest"]}}}],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "dep_cve_check", "informationUri": "https://osv.dev", "rules": []}},
            "results": results,
        }],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--requirements", help="pip の requirements.txt")
    ap.add_argument("--npm-lock", help="npm の package-lock.json")
    ap.add_argument("--out", default="dep_cve.sarif", help="SARIF の出力先")
    ap.add_argument("--timeout", type=float, default=TIMEOUT)
    args = ap.parse_args()

    targets = []  # (ecosystem, manifest_path, name, version)
    if args.requirements:
        for name, version in parse_requirements(args.requirements):
            targets.append(("PyPI", args.requirements, name, version))
    if args.npm_lock:
        for name, version in parse_npm_lock(args.npm_lock):
            targets.append(("npm", args.npm_lock, name, version))

    if not targets:
        print("確認対象がありません。--requirements か --npm-lock を指定してください。", file=sys.stderr)
        return 1

    findings, errors = [], []
    for ecosystem, manifest, name, version in targets:
        try:
            resp = osv_query(name, version, ecosystem, timeout=args.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            errors.append({"manifest": manifest, "name": name, "version": version,
                            "reason": "OSV に接続できなかった（%s）" % e})
            continue
        for vuln in resp.get("vulns", []):
            findings.append({
                "manifest": manifest, "name": name, "version": version,
                "osv_id": vuln.get("id", "OSV-UNKNOWN"),
                "cve": cve_alias(vuln),
                "summary": vuln.get("summary", ""),
                "level": severity_level(vuln),
                "explicit": bool((vuln.get("database_specific") or {}).get("severity")),
                "fixed": fixed_versions_for(vuln, name, ecosystem),
            })

    findings = merge_by_cve(findings)
    sarif = to_sarif(findings, errors)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)

    print("対象: %d件 / 既知の脆弱性: %d件（CVE 単位。同じ CVE の重複エントリはまとめた）/ 確認できなかった: %d件" % (len(targets), len(findings), len(errors)))
    for e in errors:
        print("  ⚠ %s %s: %s" % (e["name"], e["version"], e["reason"]))
    print("出力: %s（vuln_triage.html に読み込めます）" % args.out)
    if findings:
        return 1
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
