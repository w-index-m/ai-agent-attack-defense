#!/usr/bin/env python3
"""shared/taxonomy.json を唯一の定義（single source of truth）として、各ツールが
それに追従しているかを検査する「ズレ検知（drift guard）」。

目的: 検知/防御タグ（R1–R7 / ③）・攻撃連鎖・対応スキャナ・検知ルールの網羅表の
定義が各ファイルに点在してコピーされているため、片方だけ更新して他方を忘れる
「最新化漏れ」が起きやすい。この検査を CI に入れ、ズレがあればビルドを失敗させる。

検査項目:
  1. netcheck.py / vuln_triage.html が使う R タグが taxonomy に定義済みか
  2. vuln_triage.html の対応スキャナ（parseOne と絞り込み）が taxonomy と一致するか
  3. vuln_triage.html の攻撃連鎖（CHAIN）が taxonomy と一致するか
  4. detections/ の各バックエンドのルール有無が taxonomy の網羅表と一致するか
  5. R1–R7 が detections/README.md と defense-detection-notes.md に記載されているか

標準ライブラリだけで動く（Python 3.8+）。外部ネットワークもサブプロセスも使わない。
    python3 -I tools/check_consistency.py
"""
import ast
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rp(*parts):
    return os.path.join(ROOT, *parts)


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def tag_like(s):
    """R タグらしい文字列か（R1..R9 / ③ で始まる）。"""
    return bool(re.fullmatch(r"R\d+", s)) or s.startswith("③")


def python_string_literals(src):
    """Python ソースから文字列リテラルだけを取り出す（コメントは対象外）。"""
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(node.value)
    return out


def quoted_values_for_key(src, key):
    """JS/JSON 風ソースから `key:"..."` / `key="..."` の値を集める。"""
    vals = []
    for m in re.finditer(r"[\s,{(]%s\s*[:=]\s*\"([^\"]*)\"" % re.escape(key), src):
        vals.append(m.group(1))
    return vals


def extract_js_array(src, name):
    """`var NAME=[ "...","..." ];` の文字列要素を取り出す。"""
    m = re.search(r"var\s+%s\s*=\s*\[(.*?)\]\s*;" % re.escape(name), src, re.S)
    if not m:
        return None
    return re.findall(r"\"((?:[^\"\\]|\\.)*)\"", m.group(1))


def main():
    errors = []
    tax = json.loads(read(rp("shared", "taxonomy.json")))
    catalog = set(tax["detection_tags"].keys())
    scanners = set(tax["triage_scanners"])

    # 1. netcheck.py / vuln_triage.html が使う R タグは定義済みか --------------
    nc_src = read(rp("netcheck", "netcheck.py"))
    nc_tags = {s for s in python_string_literals(nc_src) if tag_like(s)}
    for t in sorted(nc_tags - catalog):
        errors.append("netcheck/netcheck.py: 未定義の検知/防御タグ %r。shared/taxonomy.json の detection_tags に追加してください。" % t)

    vt_src = read(rp("vuln_triage.html"))
    vt_tags = {s for s in quoted_values_for_key(vt_src, "r") if tag_like(s)}
    for t in sorted(vt_tags - catalog):
        errors.append("vuln_triage.html: 未定義の検知/防御タグ %r。shared/taxonomy.json の detection_tags に追加してください。" % t)

    # 2. vuln_triage の対応スキャナが taxonomy と一致するか ---------------------
    parse_tools = set(re.findall(r"tool\s*=\s*\"([a-z0-9]+)\"", vt_src))
    if parse_tools != scanners:
        errors.append("vuln_triage.html: parseOne の対応スキャナ %s が shared/taxonomy.json の triage_scanners %s と一致しません。"
                      % (sorted(parse_tools), sorted(scanners)))

    sel = re.search(r"id=\"f-tool\".*?</select>", vt_src, re.S)
    if sel:
        opts = set(re.findall(r"<option value=\"([a-z0-9]+)\">", sel.group(0)))
        if opts != scanners:
            errors.append("vuln_triage.html: ツール絞り込み（f-tool）の選択肢 %s が triage_scanners %s と一致しません。"
                          % (sorted(opts), sorted(scanners)))
    else:
        errors.append("vuln_triage.html: ツール絞り込み（id=\"f-tool\"）が見つかりません。")

    # 3. vuln_triage の攻撃連鎖（CHAIN）が taxonomy と一致するか ----------------
    chain = extract_js_array(vt_src, "CHAIN")
    if chain is None:
        errors.append("vuln_triage.html: 攻撃連鎖（var CHAIN）が見つかりません。")
    elif chain != tax["attack_chain"]:
        errors.append("vuln_triage.html: 攻撃連鎖（CHAIN）が shared/taxonomy.json の attack_chain と一致しません。どちらかに合わせてください。")

    # 4. detections の網羅表どおりにルールが存在するか -------------------------
    cov = tax["detections_coverage"]
    backends = cov["backends"]
    for tag, row in cov["matrix"].items():
        n = tag[1:]  # "R3" -> "3"
        for backend, expected in row.items():
            be = backends[backend]
            d = rp(*be["dir"].split("/"))
            if be["mode"] == "per_tag_file":
                hits = glob.glob(os.path.join(d, "r%s_*.%s" % (n, be["ext"])))
                if expected and not hits:
                    errors.append("detections/%s: %s のルールファイル（r%s_*.%s）が見つかりません（網羅表では present）。追加するか taxonomy の matrix を直してください。"
                                  % (backend, tag, n, be["ext"]))
                if not expected and hits:
                    errors.append("detections/%s: %s のルールファイルが存在します（%s）が、網羅表では未対応（false）です。taxonomy の matrix を true にしてください。"
                                  % (backend, tag, ", ".join(os.path.basename(h) for h in hits)))
            else:  # combined_file（falco など）: present のみ、タグ参照の有無で確認
                if expected:
                    body = "".join(read(p) for p in glob.glob(os.path.join(d, "*.%s" % be["ext"])))
                    if not re.search(r"\b%s\b" % re.escape(tag), body):
                        errors.append("detections/%s: 統合ファイル内に %s の参照が見つかりません（網羅表では present）。"
                                      % (backend, tag))

    # 5. R1–R7 がノート類に記載されているか -----------------------------------
    for doc in ("security-scan/detections/README.md", "security-scan/defense-detection-notes.md"):
        text = read(rp(*doc.split("/")))
        for tag in ("R1", "R2", "R3", "R4", "R5", "R6", "R7"):
            if tag not in text:
                errors.append("%s: %s の記載が見つかりません。" % (doc, tag))

    # 結果 --------------------------------------------------------------------
    if errors:
        print("❌ 定義のズレ（最新化漏れ）を検出しました:\n")
        for e in errors:
            print("  - " + e)
        print("\n直し方: shared/README.md の「追加のチェックリスト」に従い、shared/taxonomy.json を唯一の定義として各ツールを合わせてください。")
        return 1
    print("✅ 整合性チェック OK: 検知/防御タグ・スキャナ・攻撃連鎖・検知ルールの網羅表は shared/taxonomy.json と一致しています。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
