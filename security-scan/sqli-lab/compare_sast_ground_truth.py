#!/usr/bin/env python3
"""SAST ツール（コードを読んで探す方式）の結果を、vulnerable_app.py の「正解」と比べる。

vulnerable_app.py は、11 種類の脆弱性について、脆弱版（/login など）と修正版（/login_safe など）の
ペアを持つ。SAST ツールの JSON レポート（local-ai-sast の形式：findings[].file / line / title）を読み、
- 脆弱版のルートに指摘があれば「検出」、無ければ「見逃し」
- 修正版のルートに指摘があれば「誤検知」
として数える。ルートの範囲は、ast で対象ファイルから求める（行番号が変わっても追従する）。

AI の判定（findings[].ai.verdict）がある場合は、次のように扱う（AI なしのレポートには、影響しない）:
- verdict が false_positive の指摘は、AI が自分で打ち消したものなので、検出にも誤検知にも数えず、別に一覧する。
- 脆弱版への指摘が、すべて needs_review（要確認）の場合は、「検出(要確認のみ)」とする（検出には数える）。

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


def evaluate(report, target):
    """1つのレポートを、正解と比べる。

    戻り値: dict
      per_class: [(種類, 脆弱版の状態, 修正版に指摘が出たか, 脆弱版の指摘を AI が打ち消したか)]
                 脆弱版の状態は None(見逃し) / "weak"(すべて要確認) / "strong"
      active, dismissed: 打ち消されていない指摘 / AI が打ち消した指摘
      others: 正解の表にない位置の指摘
    """
    spans = route_spans(target)
    where = lambda line: next((p for a, b, p in spans if a <= line <= b), "(関数の外)")
    findings = json.load(open(report, encoding="utf-8-sig")).get("findings", [])
    verdict = lambda f: (f.get("ai") or {}).get("verdict") or ""
    dismissed = [f for f in findings if verdict(f) == "false_positive"]
    active = [f for f in findings if verdict(f) != "false_positive"]
    hit = {}  # ルート -> その位置の、打ち消されていない指摘
    for f in active:
        hit.setdefault(where(f["line"]), []).append(f)
    dismissed_at = {where(f["line"]) for f in dismissed}

    def state(routes):
        """None=指摘なし / "weak"=すべて要確認 / "strong"=それ以外を含む"""
        fs = [f for r in routes for f in hit.get(r, [])]
        if not fs:
            return None
        return "weak" if all(verdict(f) == "needs_review" for f in fs) else "strong"

    per_class = []
    for kind, vuln, safe in TRUTH:
        vroutes, sroutes = ALIASES.get(vuln, {vuln}), ALIASES.get(safe, {safe})
        per_class.append((kind, state(vroutes), state(sroutes) is not None, bool(vroutes & dismissed_at)))
    known = {r for _, v, s in TRUTH for r in ALIASES.get(v, {v}) | ALIASES.get(s, {s})}
    others = {p: [f["title"] for f in fs] for p, fs in hit.items() if p not in known}
    return {"per_class": per_class, "active": active, "dismissed": dismissed, "others": others, "where": where}


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    r = evaluate(argv[1], argv[2])
    rows, detected, weak, missed, fp = [], 0, 0, 0, 0
    for kind, sv, hs, _ in r["per_class"]:
        detected += sv is not None
        weak += sv == "weak"
        missed += sv is None
        fp += hs
        label = {None: "**見逃し**", "weak": "検出(要確認のみ)", "strong": "検出"}[sv]
        rows.append("| %s | %s | %s |" % (kind, label, "**誤検知**" if hs else "OK"))

    print("| 脆弱性の種類 | 脆弱版 | 修正版 |\n|---|---|---|")
    print("\n".join(rows))
    print("\n指摘 %d 件 / 検出 %d/11(うち要確認のみ %d)、見逃し %d/11、修正版の誤検知 %d"
          % (len(r["active"]), detected, weak, missed, fp))
    if r["dismissed"]:
        print("AI が打ち消した指摘(上の数には含めない) %d 件: %s" % (
            len(r["dismissed"]), "; ".join("%s: %s" % (r["where"](f["line"]), f["title"]) for f in r["dismissed"])))
    if r["others"]:
        print("正解の表にない位置の指摘: " + "; ".join("%s: %s" % (p, ", ".join(sorted(set(t)))) for p, t in r["others"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
