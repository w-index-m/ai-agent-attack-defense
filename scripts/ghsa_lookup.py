#!/usr/bin/env python3
"""GitHub Security Advisory（GHSA）の構造化データを取得し、影響版・修正版・CWE・
重大度を、整形した Markdown で出力する。

目的：これまで本リポジトリで、GHSA のページを LLM に読ませて要約していたが、
要約の過程で内容を取り違える誤り（例：2つの CVE の中身を混同する）が実際に
起きた。GitHub の公開 API は、アドバイザリを構造化データ（JSON）で返すため、
**フィールドをそのまま転記するだけ**にすれば、同じ種類の誤りを防げる。要約・
解釈は行わない。

確認専用：
- GHSA ID または CVE 番号を渡すと、公開情報を読み取るだけ。
- 攻撃・悪用は行わない。

依存は標準ライブラリのみ（urllib.request）。

使い方:
    python3 scripts/ghsa_lookup.py --ghsa GHSA-xjw9-4gw8-4rqx --out report.md
    python3 scripts/ghsa_lookup.py --cve CVE-2026-26030 --cve CVE-2026-25592 --out report.md
    python3 scripts/ghsa_lookup.py --ghsa GHSA-xjw9-4gw8-4rqx --json-out raw.json

検証状況: GitHub の公開 Advisories API（https://api.github.com/advisories/...）への
実通信は、Windows の PC で確認済み（2026-10-30。--ghsa 1件、--cve 2件とも取得
成功、失敗 0件）。JSON のパースと Markdown への整形は、ローカルのモックサーバーでも
検証済み（詳細: security-scan/ghsa-lookup-notes.md）。取得内容そのものの照合
（GitHub 上のページとの突き合わせ）は、別途行うこと。
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request

API_BASE = "https://api.github.com"
TIMEOUT = 10.0
UA = "ai-agent-attack-defense/ghsa_lookup"


def _get(url, timeout):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": UA,
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8")), dict(r.headers)


def fetch_by_ghsa(ghsa_id, timeout=TIMEOUT):
    """GET /advisories/{ghsa_id} — 1件を返す。見つからなければ None。"""
    try:
        data, _ = _get("%s/advisories/%s" % (API_BASE, ghsa_id), timeout)
        return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def fetch_by_cve(cve_id, timeout=TIMEOUT):
    """GET /advisories?cve_id=... — 0件以上のリストを返す。"""
    data, _ = _get("%s/advisories?cve_id=%s" % (API_BASE, cve_id), timeout)
    return data if isinstance(data, list) else []


def _patched_version(vuln):
    """patched_versions（文字列）と first_patched_version（オブジェクト）の
    両方の API の形に対応する。"""
    if vuln.get("first_patched_version"):
        v = vuln["first_patched_version"]
        if isinstance(v, dict):
            return v.get("identifier")
        return v
    return vuln.get("patched_versions")


def _cvss(adv):
    """cvss（単一）と cvss_severities（複数版）の両方の API の形に対応する。
    見つかった値をそのまま返し、推測で補わない。"""
    out = []
    if adv.get("cvss") and adv["cvss"].get("vector_string"):
        out.append((adv["cvss"].get("score"), adv["cvss"].get("vector_string")))
    sevs = adv.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        v = sevs.get(key)
        if v and v.get("vector_string"):
            out.append((v.get("score"), v.get("vector_string")))
    return out


def to_markdown(adv):
    """アドバイザリ 1件を、Markdown の節として整形する。フィールドの転記のみで、
    要約・言い換えは行わない。"""
    lines = []
    ghsa_id = adv.get("ghsa_id", "(GHSA ID 不明)")
    cve_id = adv.get("cve_id")
    lines.append("## %s%s" % (ghsa_id, "（%s）" % cve_id if cve_id else ""))
    lines.append("")
    if adv.get("withdrawn_at"):
        lines.append("> ⚠️ **このアドバイザリは取り下げられています**（withdrawn_at: %s）。内容を信用しないこと。" % adv["withdrawn_at"])
        lines.append("")
    lines.append("- **概要**: %s" % adv.get("summary", "(無し)"))
    lines.append("- **重大度**: %s" % adv.get("severity", "(無し)"))
    for score, vector in _cvss(adv):
        lines.append("- **CVSS**: %s（%s）" % (score if score is not None else "(スコア無し)", vector))
    cwes = adv.get("cwes") or []
    if cwes:
        lines.append("- **CWE**: " + ", ".join("%s（%s）" % (c.get("cwe_id"), c.get("name")) for c in cwes))
    lines.append("- **公表日**: %s" % adv.get("published_at", "(無し)"))
    lines.append("- **最終更新**: %s" % adv.get("updated_at", "(無し)"))
    lines.append("- **状態**: %s" % adv.get("state", "(無し)"))
    lines.append("- **GitHub 上のページ**: %s" % adv.get("html_url", "(無し)"))
    vulns = adv.get("vulnerabilities") or []
    if vulns:
        lines.append("")
        lines.append("### 影響を受けるパッケージ")
        lines.append("")
        lines.append("| エコシステム | パッケージ | 影響を受ける範囲 | 修正版 |")
        lines.append("|---|---|---|---|")
        for v in vulns:
            pkg = v.get("package") or {}
            lines.append("| %s | %s | %s | %s |" % (
                pkg.get("ecosystem", "?"), pkg.get("name", "?"),
                v.get("vulnerable_version_range", "?"),
                _patched_version(v) or "(無し)"))
    refs = adv.get("references") or []
    if refs:
        lines.append("")
        lines.append("### 参照")
        for r in refs:
            url = r.get("url") if isinstance(r, dict) else r
            lines.append("- %s" % url)
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ghsa", action="append", default=[], help="GHSA ID（繰り返し指定可）")
    ap.add_argument("--cve", action="append", default=[], help="CVE 番号（繰り返し指定可）")
    ap.add_argument("--out", default="ghsa_report.md", help="Markdown の出力先")
    ap.add_argument("--json-out", help="生のレスポンスを JSON でも保存する場合の出力先")
    ap.add_argument("--timeout", type=float, default=TIMEOUT)
    ap.add_argument("--delay", type=float, default=1.0, help="API 呼び出しの間隔（秒）。レート制限への配慮")
    args = ap.parse_args()

    if not args.ghsa and not args.cve:
        print("--ghsa か --cve を、少なくとも1つ指定してください。", file=sys.stderr)
        return 1

    advisories = []
    errors = []

    for ghsa_id in args.ghsa:
        try:
            adv = fetch_by_ghsa(ghsa_id, timeout=args.timeout)
        except (urllib.error.URLError, OSError) as e:
            errors.append("%s: 接続できなかった（%s）" % (ghsa_id, e))
            continue
        if adv is None:
            errors.append("%s: 見つからなかった（404）" % ghsa_id)
        else:
            advisories.append(adv)
        time.sleep(args.delay)

    for cve_id in args.cve:
        try:
            results = fetch_by_cve(cve_id, timeout=args.timeout)
        except (urllib.error.URLError, OSError) as e:
            errors.append("%s: 接続できなかった（%s）" % (cve_id, e))
            continue
        if not results:
            errors.append("%s: 対応する GHSA が見つからなかった" % cve_id)
        else:
            advisories.extend(results)
        time.sleep(args.delay)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("# GHSA 取得結果\n\n")
        f.write("GitHub の公開 Advisories API から、フィールドをそのまま転記したもの（要約・解釈はしていない）。\n\n")
        for adv in advisories:
            f.write(to_markdown(adv))
            f.write("\n---\n\n")
        if errors:
            f.write("## 取得できなかったもの\n\n")
            for e in errors:
                f.write("- %s\n" % e)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(advisories, f, ensure_ascii=False, indent=2)

    print("取得: %d件 / 失敗: %d件" % (len(advisories), len(errors)))
    for e in errors:
        print("  ⚠ %s" % e)
    print("出力: %s" % args.out)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
