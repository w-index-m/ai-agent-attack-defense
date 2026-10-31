#!/usr/bin/env python3
"""SAST ツール（コードを読んで探す方式）の結果を、vulnerable_app.py の「正解」と比べる。

vulnerable_app.py は、11 種類の脆弱性について、脆弱版（/login など）と修正版（/login_safe など）の
ペアを持つ。SAST ツールの JSON レポート（local-ai-sast の形式：findings[].file / line / title）を読み、
- 脆弱版のルートに、**その種類に合う指摘**(タイトルのキーワードで判定)があれば「検出」、無ければ「見逃し」
- 修正版のルートに、その種類に合う指摘があれば「誤検知」
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

# (種類, 脆弱なルート, 修正版のルート, 指摘のタイトルに含まれるキーワード(小文字))
# ルートに指摘が出ていても、タイトルがその種類に合わなければ、検出とは数えない
# (例: /login に出た「ハードコードされたパスワード」の誤検知で、SQL インジェクションを検出したことにしない)。
TRUTH = [
    ("SQL インジェクション", "/login", "/login_safe", ("sql injection", "sqli")),
    ("反射型 XSS", "/search", "/search_safe", ("xss", "cross-site scripting")),
    ("OS コマンドインジェクション", "/diag", "/diag_safe", ("command injection", "cmdi")),
    ("パストラバーサル", "/file", "/file_safe", ("path traversal", "directory traversal")),
    ("CSRF", "/csrf_transfer", "/csrf_transfer_safe", ("csrf", "cross-site request forgery")),
    ("アクセス制御の不備(IDOR)", "/idor_account", "/idor_account_safe", ("idor", "bola", "unauthorized access", "access control")),
    ("安全でないデシリアライズ", "/deserialize", "/deserialize_safe", ("deserializ",)),
    ("格納型 XSS", "/review", "/review_safe", ("xss", "cross-site scripting")),
    ("マスアサインメント", "/signup", "/signup_safe", ("mass assignment",)),
    ("SSRF", "/fetch_url", "/fetch_url_safe", ("ssrf", "server-side request forgery")),
    ("アカウント列挙", "/register", "/register_safe", ("enumeration",)),
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
      per_class: [(種類, 脆弱版の状態, 修正版にその種類の指摘が出たか, 脆弱版のその種類の指摘を AI が打ち消したか)]
                 脆弱版の状態は None(見逃し) / "weak"(すべて要確認) / "strong"
      active, dismissed: 打ち消されていない指摘 / AI が打ち消した指摘
      others: どの種類の検出にも数えなかった、打ち消されていない指摘(ルート: タイトル)
    """
    spans = route_spans(target)
    where = lambda line: next((p for a, b, p in spans if a <= line <= b), "(関数の外)")
    findings = json.load(open(report, encoding="utf-8-sig")).get("findings", [])
    verdict = lambda f: (f.get("ai") or {}).get("verdict") or ""
    dismissed = [f for f in findings if verdict(f) == "false_positive"]
    active = [f for f in findings if verdict(f) != "false_positive"]
    matches = lambda f, kws: any(k in f.get("title", "").lower() for k in kws)

    def pick(fs, routes, kws):
        return [f for f in fs if where(f["line"]) in routes and matches(f, kws)]

    per_class, used = [], set()
    for kind, vuln, safe, kws in TRUTH:
        vroutes, sroutes = ALIASES.get(vuln, {vuln}), ALIASES.get(safe, {safe})
        vf, sf = pick(active, vroutes, kws), pick(active, sroutes, kws)
        used.update(id(f) for f in vf + sf)
        state = None if not vf else ("weak" if all(verdict(f) == "needs_review" for f in vf) else "strong")
        per_class.append((kind, state, bool(sf), bool(pick(dismissed, vroutes, kws))))
    others = {}
    for f in active:
        if id(f) not in used:
            others.setdefault(where(f["line"]), []).append(f["title"])
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
        print("どの種類の検出にも数えなかった指摘: " + "; ".join("%s: %s" % (p, ", ".join(sorted(set(t)))) for p, t in r["others"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
