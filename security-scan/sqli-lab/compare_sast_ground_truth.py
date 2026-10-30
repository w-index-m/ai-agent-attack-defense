#!/usr/bin/env python3
"""SAST ツール（コードを読んで探す方式）の結果を、vulnerable_app.py の「正解」と比べる。

vulnerable_app.py は、11 種類の脆弱性について、脆弱版（/login など）と修正版（/login_safe など）の
ペアを持つ。SAST ツールの JSON レポート（local-ai-sast の形式：findings[].file / line / title）を読み、
- 脆弱版のルートに指摘があれば「検出」、無ければ「見逃し」
- 修正版のルートに指摘があれば「誤検知」
として数える。ルートの範囲は、ast で対象ファイルから求める（行番号が変わっても追従する）。

読み取り専用：ファイルを読んで、表を出すだけ。ネットワークには出ない。

使い方:
    python3 compare_sast_ground_truth.py report.json vulnerable_app.py
"""
import ast
import json
import sys

# (種類, 脆弱なルート, 修正版のルート)
TRUTH = [
    ("SQL インジェクション", "/login", "/login_safe"),
    ("反射型 XSS", "/search", "/search_safe"),
    ("OS コマンドインジェクション", "/diag", "/diag_safe"),
    ("パストラバーサル", "/file", "/file_safe"),
    ("CSRF", "/csrf_transfer", "/csrf_transfer_safe"),
    ("アクセス制御の不備(IDOR)", "/idor_account", "/idor_account_safe"),
    ("安全でないデシリアライズ", "/deserialize", "/deserialize_safe"),
    ("格納型 XSS", "/review", "/review_safe"),
    ("マスアサインメント", "/signup", "/signup_safe"),
    ("SSRF", "/fetch_url", "/fetch_url_safe"),
    ("アカウント列挙", "/register", "/register_safe"),
]
# 格納型 XSS は、投稿(/review)と表示(/reviews)の2つのルートにまたがる。どちらに指摘が出ても、検出とみなす。
ALIASES = {"/review": {"/review", "/reviews"}, "/review_safe": {"/review_safe", "/reviews_safe"}}


def route_spans(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for d in node.decorator_list:
                if isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "route" and d.args:
                    spans.append((node.lineno, node.end_lineno, d.args[0].value))
    return sorted(spans)


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    report, target = argv[1], argv[2]
    spans = route_spans(target)
    where = lambda line: next((p for a, b, p in spans if a <= line <= b), "(関数の外)")
    findings = json.load(open(report, encoding="utf-8-sig")).get("findings", [])
    hit = {}
    for f in findings:
        hit.setdefault(where(f["line"]), []).append(f["title"])

    rows, detected, missed, fp = [], 0, 0, 0
    for kind, vuln, safe in TRUTH:
        hv = any(r in hit for r in ALIASES.get(vuln, {vuln}))
        hs = any(r in hit for r in ALIASES.get(safe, {safe}))
        detected += hv
        missed += not hv
        fp += hs
        rows.append("| %s | %s | %s |" % (kind, "検出" if hv else "**見逃し**", "**誤検知**" if hs else "OK"))
    known = {r for _, v, s in TRUTH for r in ALIASES.get(v, {v}) | ALIASES.get(s, {s})}
    others = {p: t for p, t in hit.items() if p not in known}

    print("| 脆弱性の種類 | 脆弱版 | 修正版 |\n|---|---|---|")
    print("\n".join(rows))
    print("\n指摘 %d 件 / 検出 %d/11、見逃し %d/11、修正版の誤検知 %d" % (len(findings), detected, missed, fp))
    if others:
        print("正解の表にない位置の指摘: " + "; ".join("%s: %s" % (p, ", ".join(sorted(set(t)))) for p, t in others.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
