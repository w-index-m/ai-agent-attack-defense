#!/usr/bin/env python3
"""dep_cve_check.py が OSV から得た結果を、GitHub の Advisories API と突き合わせる。

目的：OSV が返した CVE ごとの「修正版」が、GitHub Security Advisory（GHSA）の「修正版」
（first_patched_version）と一致するかを、自動で確かめる。目視で1件ずつ照合する代わり。
両者は、別のデータベースなので、一致すれば、取り違えや取り込みの誤りの可能性が下がる。
一致しない場合は、誤りとは限らない（ブランチごとに複数の修正版がある、データベースの更新の
遅れなど）。「要目視」として、差を出す。

確認専用：公開 API を読み取るだけ。依存は標準ライブラリのみ。ghsa_lookup.py の取得処理を使う。

使い方:
    python3 scripts/dep_cve_check.py --requirements req.txt --out dep.sarif
    python3 scripts/crosscheck_osv_ghsa.py dep.sarif
    python3 scripts/crosscheck_osv_ghsa.py dep.sarif --out crosscheck.md

終了コード: 0=すべて一致 / 1=一致しないもの・突き合わせられないものがある。
GITHUB_TOKEN（または GH_TOKEN）があれば、認証つきで呼ぶ（ghsa_lookup.py と同じ）。
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghsa_lookup  # noqa: E402

# OSV のエコシステム名 → GHSA のエコシステム名
GHSA_ECOSYSTEM = {"PyPI": "pip", "npm": "npm", "NuGet": "nuget", "Go": "go"}
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _norm_name(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _norm_ver(v):
    v = str(v).strip()
    return v[1:] if v.startswith("v") else v


def osv_findings(path):
    """SARIF から、(CVE, エコシステム, パッケージ, 版, 修正版の集合) を、重複なしで返す。
    properties を持たない古い SARIF や、確認不能の報告は除く。"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    seen, out = set(), []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            props = r.get("properties") or {}
            cve = r.get("ruleId", "")
            if not ghsa_lookup._CVE_RE.match(cve) or not props.get("package") or not props.get("ecosystem"):
                continue
            key = (cve, props["ecosystem"], _norm_name(props["package"]))
            if key in seen:
                continue
            seen.add(key)
            fixed = {_norm_ver(v) for v in props.get("fixed", []) if not _COMMIT.match(str(v))}
            out.append((cve, props["ecosystem"], props["package"], props.get("version", ""), fixed))
    return out


def ghsa_fixed(advisories, ecosystem, package):
    """GHSA のアドバイザリ群から、この（エコシステム, パッケージ）の修正版の集合を返す。
    該当するパッケージが無ければ None。"""
    want_eco, want_name = GHSA_ECOSYSTEM.get(ecosystem, ecosystem), _norm_name(package)
    found, fixed = False, set()
    for adv in advisories:
        for v in adv.get("vulnerabilities") or []:
            pkg = v.get("package") or {}
            if str(pkg.get("ecosystem", "")).lower() == want_eco and _norm_name(pkg.get("name", "")) == want_name:
                found = True
                p = ghsa_lookup._patched_version(v)
                if p:
                    fixed.add(_norm_ver(p))
    return fixed if found else None


def ghsa_packages(advisories):
    """GHSA 側に載っている（エコシステム/パッケージ名）の一覧。「突き合わせ不可」の原因を切り分けるための診断用。"""
    out = set()
    for adv in advisories:
        for v in adv.get("vulnerabilities") or []:
            pkg = v.get("package") or {}
            out.add("%s/%s" % (pkg.get("ecosystem", "?"), pkg.get("name", "?")))
    return sorted(out)


def judge(osv_fixed, ghsa_set, advisories):
    if not advisories:
        return "GHSA に無い", ""
    if ghsa_set is None:
        return "突き合わせ不可", "GHSA にこのパッケージの記載が無い"
    if osv_fixed == ghsa_set:
        return "一致", ""
    if osv_fixed & ghsa_set:
        return "要目視", "一部のみ一致"
    return "要目視", "一致しない"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sarif", nargs="+", help="dep_cve_check.py の SARIF（複数可）")
    ap.add_argument("--out", help="結果を Markdown でも保存する場合の出力先")
    ap.add_argument("--timeout", type=float, default=ghsa_lookup.TIMEOUT)
    ap.add_argument("--delay", type=float, default=1.0, help="API 呼び出しの間隔（秒）")
    args = ap.parse_args()

    findings, seen = [], set()
    for path in args.sarif:
        for f in osv_findings(path):
            if f[:3] not in seen:
                seen.add(f[:3])
                findings.append(f)
    if not findings:
        print("突き合わせる対象がありません（properties を持つ SARIF が必要です。dep_cve_check.py で作り直してください）。")
        return 0

    cache, rows = {}, []
    for cve, eco, pkg, ver, osv_fixed in findings:
        if cve not in cache:
            try:
                cache[cve] = ghsa_lookup.fetch_by_cve(cve, timeout=args.timeout)
            except (urllib.error.URLError, OSError) as e:
                cache[cve] = e
            time.sleep(args.delay)
        advs = cache[cve]
        if isinstance(advs, Exception):
            rows.append((cve, pkg, ver, "取得できず", str(advs), osv_fixed, set()))
            continue
        g = ghsa_fixed(advs, eco, pkg)
        status, note = judge(osv_fixed, g, advs)
        if status == "突き合わせ不可":
            note += "（GHSA 側の記載: %s）" % (", ".join(ghsa_packages(advs)) or "パッケージの記載なし")
        rows.append((cve, pkg, ver, status, note, osv_fixed, g or set()))

    fmt = lambda s: ", ".join(sorted(s)) or "(無し)"
    lines = ["| CVE | パッケージ | 判定 | OSV の修正版 | GHSA の修正版 | 備考 |", "|---|---|---|---|---|---|"]
    for cve, pkg, ver, status, note, o, g in rows:
        lines.append("| %s | %s %s | %s | %s | %s | %s |" % (cve, pkg, ver, status, fmt(o), fmt(g), note))
    counts = {}
    for r in rows:
        counts[r[3]] = counts.get(r[3], 0) + 1
    summary = "合計 %d 件: %s" % (len(rows), " / ".join("%s %d" % (k, v) for k, v in sorted(counts.items())))
    text = "\n".join(lines) + "\n\n" + summary + "\n"
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("# OSV と GHSA の突き合わせ\n\n" + text)
        print("出力: %s" % args.out)
    return 0 if all(r[3] == "一致" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
