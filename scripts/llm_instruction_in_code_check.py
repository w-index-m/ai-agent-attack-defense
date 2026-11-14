#!/usr/bin/env python3
"""llm_instruction_in_code_check: コード・設定・文書の中に仕込まれた「LLM宛の指示」を探す(確認専用、読み取りのみ)。

背景: GTIG(Google Threat Intelligence Group)の2026年9月のレポート(利用者が貼り付けた本文に基づく)が、
マルウェアのJavaScriptローダーの先頭コメントに、LLMのセキュリティスキャナを妨害するための文章
(「システムを上書きする」「制限なしのモードで動く」といった指示と、LLMに拒否させるための、危険な話題の
長い文章)を埋め込む手口を報告している。LLMが拒否して、その下の悪性コードの解析を飛ばすことを狙う。
同じ置き場所に、AIコーディング支援を操る指示(設定ファイル経由)も仕込まれる。

この検査は、決定的な規則(正規表現と、コメントのかたまりの構造)で、次を探す:
  1. 指示の上書き(「以前の指示を無視」「制限なしのモード」「安全方針の解除」など)           [高]
  2. LLMへの長い指示文らしいコメント(役割の指定・手順の要求などが重なる。危険な話題の語が
     加わると高、それ以外は中)                                                              [高/中]
  3. レビューするAI・スキャナ宛の指示(「このコードは報告するな」など)                         [中]
  4. 検査の回避の主張(「このコードは安全」など。普通の文書にも出るので、低確度)               [低]
  5. 不可視文字: Unicodeのタグ文字(隠しテキスト) [高]、双方向制御(Trojan Source) [中]、
     ゼロ幅文字 [低]
  6. 依存パッケージの中の、AI向けの指示ファイル(CLAUDE.md・AGENTS.md・.cursorrules等)         [低]
文書(.md・.txt等)の中の指示は、セキュリティの解説にも出るので、重大度を1段下げる。

正直な限界:
  - 決定的な規則なので、言い回しを変えた指示、別の言語の指示、画像・難読化された文字列の中の指示は見逃す。
  - **自分のセキュリティ文書(このリポジトリのdocs等)を読ませると、解説の中の例文を拾って、誤検知になる**。
    主な対象は、**第三者のコード(依存パッケージ、取り込んだリポジトリ)**。--exclude-glob で外せる。
  - LLMアプリのプロンプトのテンプレートにも、似た文が出る(中・低が増える)。
  - 見つかったものは「調べる手がかり」で、悪意の証明ではない。

出力は、画面の一覧と、--out を指定すると vuln_triage.html に読み込めるSARIF。表示する文は、一致した
前後の短い部分だけで、長い文章は転記しない。

使用例:
  python3 scripts/llm_instruction_in_code_check.py --path node_modules
  python3 scripts/llm_instruction_in_code_check.py --path . --exclude-glob "docs/*" --min-severity medium --out llm_instr.sarif
終了コード: 0(見つからなかった) / 1(見つかった) / 2(読み取りエラー)
標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse
import fnmatch
import json
import os
import re
import sys
import unicodedata

SEV_RANK = {"low": 0, "medium": 1, "high": 2}
SEV_LEVEL = {"low": "note", "medium": "warning", "high": "error"}
DOC_EXT = (".md", ".txt", ".rst", ".html", ".htm")
CONFIG_EXT = (".json", ".yml", ".yaml", ".toml", ".cfg", ".ini")
CODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".go", ".rs", ".java", ".kt", ".c", ".h",
            ".cpp", ".cs", ".php", ".sh", ".ps1", ".lua", ".swift")
SPECIAL_NAMES = (".cursorrules",)
SKIP_DIRS = {".git", "__pycache__", ".hg", ".svn"}
AI_INSTRUCTION_NAMES = {"claude.md", "agents.md", ".cursorrules", "copilot-instructions.md"}
DEP_MARKERS = ("/node_modules/", "/site-packages/", "/vendor/", "/.venv/")

I = re.I
# (ID, 重大度, ラベル, 正規表現)
PHRASES = [
    ("override", "high", "指示の上書き", re.compile(
        r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|preceding|system)"
        r"\s+(instructions?|prompts?|rules?|guidelines?|directions?|messages?)"
        r"|\bforget\s+(everything|all)\s+(above|before|you\s+(were|have\s+been)\s+told)"
        r"|\byou\s+are\s+now\s+(in\s+)?(an?\s+)?(unrestricted|jailbroken|uncensored|unfiltered)\b"
        r"|\b(unrestricted|jailbreak(ed)?|developer|god)\s+mode\b"
        r"|\bsystem\s+override\b"
        r"|\b(all\s+)?safety\s+(guidelines?|filters?|restrictions?|policies)\s+(are\s+|have\s+been\s+)?(suspended|disabled|removed|lifted)\b"
        r"|\b(reveal|print|show|output|leak|repeat|disclose)\s+(your|the)\s+(system\s+prompt|hidden\s+instructions?|initial\s+instructions?)", I)),
    ("override-ja", "high", "指示の上書き(日本語)", re.compile(
        r"(以前|これまで|上記|前)の(指示|命令|プロンプト)を(すべて|全て)?(無視|忘れ|破棄)"
        r"|(システムプロンプト|指示)を(無視|出力|表示|漏ら)"
        r"|安全(性)?(の)?(ガイドライン|制限|フィルタ)を(解除|無効|停止|無視)"
        r"|あなたは(今から|これから)[^。\n]{0,20}(制限なし|無制限|脱獄)")),
    ("directed", "medium", "レビューするAI・スキャナ宛の指示", re.compile(
        r"\b(ai|llm|assistant|agent|copilot|claude|reviewer|scanner|analy[sz]er)\b[\s,:;-]{1,4}(please\s+)?"
        r"(ignore|skip|do\s+not\s+(report|flag|scan|analy[sz]e|review|mention)|don'?t\s+(report|flag|scan|analy[sz]e|review|mention))\b", I)),
    ("evasion", "low", "検査の回避の主張", re.compile(
        r"\b(do\s+not|don'?t|never)\s+(report|flag|mention|scan|analy[sz]e|review)\s+(this|the\s+(following|code|file))\b"
        r"|\bthis\s+(file|code|package|script)\s+(is|has\s+been)\s+(safe|benign|harmless|reviewed|audited|verified)\b"
        r"|\b(mark|report|treat|label)\s+(this(\s+(code|file|package|script))?|it|the\s+code)\s+as\s+(safe|benign|clean|harmless)\b", I)),
]
# 長い指示文らしいコメントの手がかり(2種類以上で成立)
DIRECTIVE_CUES = [re.compile(p, I) for p in (
    r"you\s+are\s+(now|a|an)\b", r"\b(provide|produce|write|generate|explain|describe)\s+(a|an|the)\s+(complete|detailed|exhaustive|comprehensive|step-by-step)",
    r"step-by-step", r"\bsystem\s+override\b|\bunrestricted\b|\bclassified\b", r"\binclude\s*:", r"\bphase\s+[ivx\d]+\b")]
SENSITIVE_WORDS = re.compile(r"\b(weapon|biological|nuclear|chemical\s+agent|explosive|pathogen|lethal)\w*", I)
BLOCK_MIN_LINES, BLOCK_MIN_CHARS = 8, 500
TAG_RANGE = (0xE0000, 0xE007F)
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
ZERO_WIDTH = {0x200B, 0x200C, 0x2060, 0xFEFF}


def kind_of(path):
    low = path.lower()
    if low.endswith(DOC_EXT):
        return "doc"
    if low.endswith(CONFIG_EXT):
        return "config"
    return "code"


def wanted(name):
    low = name.lower()
    return low.endswith(DOC_EXT + CONFIG_EXT + CODE_EXT) or low in SPECIAL_NAMES


def clean(text, limit=100):
    out = "".join(" " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else ("" if unicodedata.category(c) == "Cf" else c)
                  for c in text)
    out = re.sub(r"\s+", " ", out).strip()
    return out if len(out) <= limit else out[: limit - 1] + "…"


def downgrade(sev, kind):
    return {"high": "medium", "medium": "low"}.get(sev, sev) if kind == "doc" else sev


def comment_text(line):
    s = line.strip()
    for p in ("//", "#", "*", "/*", "<!--", "--", ";", "'''", '"""'):
        if s.startswith(p):
            return s[len(p):].strip()
    return None


def scan_text(path, text, kind):
    """1ファイル分の内容から、(行番号, 重大度, ID, ラベル, 一致した部分の短い抜粋) の一覧を作る。"""
    hits = []
    lines = text.split("\n")
    for n, line in enumerate(lines, 1):
        if len(line) > 5000:
            line = line[:5000]
        for rid, sev, label, pat in PHRASES:
            m = pat.search(line)
            if m:
                a, b = max(0, m.start() - 20), min(len(line), m.end() + 20)
                hits.append((n, downgrade(sev, kind), rid, label, clean(line[a:b])))
        tags = sum(1 for c in line if TAG_RANGE[0] <= ord(c) <= TAG_RANGE[1])
        if tags:
            hits.append((n, "high", "hidden-tag-chars", "Unicodeのタグ文字(隠しテキストの可能性)", "%d 文字" % tags))
        bidi = sum(1 for c in line if ord(c) in BIDI)
        if bidi:
            hits.append((n, "medium", "bidi-control", "双方向制御文字(Trojan Source)", "%d 文字" % bidi))
        zw = sum(1 for i, c in enumerate(line) if ord(c) in ZERO_WIDTH and not (n == 1 and i == 0 and ord(c) == 0xFEFF))
        if zw:
            hits.append((n, "low", "zero-width", "ゼロ幅文字", "%d 文字" % zw))
    # 長い指示文らしいコメントのかたまり(コードと設定のみ。文書は対象外)
    if kind != "doc":
        block, start = [], 0
        in_triple = False
        for n, line in enumerate(lines + [""], 1):
            ct = comment_text(line)
            if line.count('"""') % 2 == 1 or line.count("'''") % 2 == 1:
                in_triple = not in_triple
            if ct is not None or in_triple:
                if not block:
                    start = n
                block.append(ct if ct is not None else line.strip())
                continue
            if block:
                body = " ".join(block)
                cues = sum(1 for c in DIRECTIVE_CUES if c.search(body))
                if (len(block) >= BLOCK_MIN_LINES or len(body) >= BLOCK_MIN_CHARS) and cues >= 2:
                    sev = "high" if SENSITIVE_WORDS.search(body) else "medium"
                    hits.append((start, sev, "long-directive-comment",
                                 "LLMへの長い指示文らしいコメント(%d行。指示の手がかり %d 種)" % (len(block), cues), clean(block[0], 60)))
                block = []
    return hits


def walk(paths, excludes, max_bytes):
    for root_arg in paths:
        if os.path.isfile(root_arg):
            yield root_arg, os.path.basename(root_arg)
            continue
        for root, dirs, files in os.walk(root_arg):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(root, d))]
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, root_arg).replace(os.sep, "/")
                if os.path.islink(full) or not wanted(name):
                    continue
                if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(full.replace(os.sep, "/"), g) for g in excludes):
                    continue
                try:
                    if os.path.getsize(full) > max_bytes:
                        continue
                except OSError:
                    continue
                yield full, rel


def scan(paths, excludes=(), max_bytes=1_000_000, min_severity="low"):
    results, errors, nfiles = [], [], 0
    for full, rel in walk(paths, excludes, max_bytes):
        nfiles += 1
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            errors.append("%s: %s" % (full, e))
            continue
        norm = "/" + full.replace(os.sep, "/")
        kind = kind_of(full)
        hits = scan_text(full, text, kind)
        if os.path.basename(full).lower() in AI_INSTRUCTION_NAMES or "/.claude/" in norm:
            if any(m in norm for m in DEP_MARKERS):
                hits.append((1, "low", "ai-instruction-file-in-dependency", "依存パッケージの中の、AI向けの指示ファイル", os.path.basename(full)))
        for n, sev, rid, label, snippet in hits:
            if SEV_RANK[sev] >= SEV_RANK[min_severity]:
                results.append({"path": full, "line": n, "severity": sev, "rule": rid, "label": label, "snippet": snippet, "kind": kind})
    results.sort(key=lambda r: (-SEV_RANK[r["severity"]], r["path"], r["line"]))
    return results, errors, nfiles


def to_sarif(results):
    return {"version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "llm_instruction_in_code_check", "rules": []}},
                      "results": [{"ruleId": "llm-instruction-in-code/" + r["rule"], "level": SEV_LEVEL[r["severity"]],
                                   "message": {"text": "%s(%s): %s" % (r["label"], r["kind"], r["snippet"])},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": r["path"].replace(os.sep, "/")},
                                                                       "region": {"startLine": r["line"]}}}],
                                   "properties": {"title": r["label"]}} for r in results]}]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", action="append", default=[], help="調べるフォルダ/ファイル(繰り返し指定可。既定: カレント)")
    ap.add_argument("--exclude-glob", action="append", default=[], help="除外するパターン(例: 'docs/*')。繰り返し指定可")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low")
    ap.add_argument("--max-file-bytes", type=int, default=1_000_000)
    ap.add_argument("--out", default="", help="SARIFの出力先(vuln_triage.html に読み込める)")
    a = ap.parse_args()
    paths = a.path or ["."]
    for p in paths:
        if not os.path.exists(p):
            print("見つかりません: %s" % p, file=sys.stderr)
            return 2
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    results, errors, nfiles = scan(paths, a.exclude_glob, a.max_file_bytes, a.min_severity)
    print("対象: %s (%d ファイル)" % (", ".join(paths), nfiles))
    print("-" * 60)
    for e in errors:
        print("読み取りに失敗: " + e, file=sys.stderr)
    if not results:
        print("LLM宛の指示らしいものは見つかりませんでした(見逃しはあり得ます。限界は --help)。")
    for r in results:
        print("  [%s] %s -> %s:%d  「%s」" % (r["severity"], r["label"], r["path"], r["line"], r["snippet"]))
    if results:
        by = {}
        for r in results:
            by[r["severity"]] = by.get(r["severity"], 0) + 1
        print("\n計 %d 件(%s)。見つかったものは「調べる手がかり」で、悪意の証明ではありません。" % (
            len(results), "・".join("%s %d" % (k, by[k]) for k in ("high", "medium", "low") if k in by)))
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(to_sarif(results), f, ensure_ascii=False, indent=2)
        print("SARIF: %s(vuln_triage.html に読み込めます)" % a.out)
    return 1 if results else (2 if errors else 0)


if __name__ == "__main__":
    sys.exit(main())
