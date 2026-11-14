#!/usr/bin/env python3
"""ai_tool_config_secret_check: AI開発ツール(AIコーディング支援・IDE拡張)の設定ファイルに、平文の秘密情報が
入っていないかを、自分のマシンで点検する(確認専用、読み取りのみ)。

背景: GTIGの2026年9月のレポート(利用者が貼り付けた本文に基づく)は、情報窃取マルウェア(ACRSTEALER)の制御者が、
AIコーディング支援の設定ファイル(Cline の secrets.json、Continue の config.yaml)を狙うファイル収集ルールを
配信したと報告している。これらは、平文のAPIキーや、モデルの接続先を保存し得て、盗まれると、被害者の有料のモデルの
割り当てと基盤が、そのまま使われる(LLMJacking)。リポジトリの秘密情報は gitleaks・Trivy が見るが、
**利用者のホームの設定ファイルは、対象外**だった。

この点検がすること:
  - 既知の設定ファイルの場所(下の KNOWN_FILES・GLOBALSTORAGE)と、--path で指定した場所を読み、
    APIキー・トークン・秘密鍵の形の文字列と、「キー」「トークン」「パスワード」などの名前の項目を探す。
  - **見つけた値は、画面にもSARIFにも、一文字も出さない**。出すのは、場所・行・種類・長さ・ファイルの権限だけ。
  - 環境変数の参照(例: ${ANTHROPIC_API_KEY}、$OPENAI_API_KEY)と、ひな形の値(YOUR_API_KEY、xxxx など)は、指摘しない
    (環境変数へ移すのが、推奨の形)。
  - POSIX では、他のユーザーが読める権限(group/other に読み取り権限)を警告する。Windows のACLは見ない。
  - 「どの場所を確認して、何が存在したか」を必ず表示する(場所の一覧が、お使いの版と合っているかを、確かめられるように)。

正直な限界:
  - **既知の場所の一覧は、私の知識に基づくもので、ツールの版やOSで違い得る**。特に Cline の保存先(VS Code の
    globalStorage の中)は、フォルダ名に claude-dev / cline / continue / roo を含むものを探す形にしている。
    見つからなければ、--path で指定する。「確認した場所」の表示で、実際に調べられたかを確かめる。
  - 形が違う秘密情報(独自の形式のトークン)、暗号化・難読化されたもの、OSのキーストアの中身は、見えない。
  - 値が「環境変数の参照」でも、そのコマンドの環境に秘密情報があること自体は、この点検の対象外。
  - このサンドボックスでは、実際の利用者のマシンの設定では、確認していない(合成ファイルのみ)。

使用例:
  python3 scripts/ai_tool_config_secret_check.py
  python3 scripts/ai_tool_config_secret_check.py --path ./myproject/.cursor --out ai_tool_secrets.sarif
終了コード: 0(見つからなかった) / 1(見つかった) / 2(指定した場所が無いなどのエラー)
標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse
import json
import math
import os
import re
import stat
import sys

# ホームからの相対パス(私の知識に基づく。版やOSで違い得る)
KNOWN_FILES = [
    ".continue/config.yaml", ".continue/config.json",
    ".claude.json", ".claude/settings.json", ".claude/settings.local.json",
    ".cursor/mcp.json", ".codex/config.toml", ".codex/auth.json",
    ".aider.conf.yml", ".config/github-copilot/hosts.json", ".config/github-copilot/apps.json",
]
# VS Code 系の globalStorage(この中の、フォルダ名に下の語を含むものを探す)
GLOBALSTORAGE = [
    ".config/Code/User/globalStorage", ".config/Cursor/User/globalStorage", ".config/VSCodium/User/globalStorage",
    "Library/Application Support/Code/User/globalStorage", "Library/Application Support/Cursor/User/globalStorage",
    "AppData/Roaming/Code/User/globalStorage", "AppData/Roaming/Cursor/User/globalStorage",
]
GLOBALSTORAGE_DIR_HINTS = ("claude-dev", "cline", "continue", "roo")
SCAN_EXT = (".json", ".yaml", ".yml", ".toml", ".env", ".conf", ".ini", ".cfg")
SCAN_NAMES = (".env", ".aider.conf.yml", ".claude.json")

KINDS = [  # (ID, 表示名, 正規表現)。上から順に当て、同じ位置を二重に数えない
    ("anthropic", "Anthropic形式のAPIキー", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openrouter", "OpenRouter形式のAPIキー", re.compile(r"sk-or-[A-Za-z0-9_\-]{20,}")),
    ("openai", "OpenAI形式のAPIキー", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}")),
    ("google", "Google APIキー", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("github", "GitHubのトークン", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}")),
    ("aws", "AWSのアクセスキーID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack", "Slackのトークン", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("huggingface", "Hugging Faceのトークン", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("groq", "Groq形式のAPIキー", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("private-key", "秘密鍵", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
]
FIELD_RE = re.compile(r"""["']?([A-Za-z0-9_\-\.]+)["']?\s*[:=]\s*["']?([^\s"',}\]#]{20,})""")
NAME_SUFFIXES = ("apikey", "api_key", "api-key", "secret", "secretkey", "secret_key", "token", "accesstoken", "access_token",
                 "authtoken", "auth_token", "refreshtoken", "refresh_token", "password", "passwd", "privatekey", "private_key", "bearer")
ENV_FIELD_RE = re.compile(r"""["']?([A-Za-z0-9_\-\.]+)["']?\s*[:=]\s*["']?(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|env:[A-Za-z_][A-Za-z0-9_]*|process\.env\.[A-Za-z_][A-Za-z0-9_]*)""")
PLACEHOLDERS = ("your", "xxxx", "<", ">", "example", "placeholder", "changeme", "dummy", "insert", "redacted", "****", "todo", "...", "fake")
MIN_ENTROPY = 3.3


def entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def is_env_reference(v):
    low = v.lower()
    return (v.startswith("$") or "${" in v or low.startswith("env:") or "process.env" in low or
            (v.startswith("%") and v.endswith("%")) or low.startswith("os.environ"))


def looks_like_path(v):
    return v.startswith(("/", "./", "../", "~")) or bool(re.match(r"^[A-Za-z]:[\\/]", v))


def secret_like_name(name):
    last = re.split(r"[\.]", name.lower())[-1]
    return last.endswith(NAME_SUFFIXES)  # max_tokens・tokenizer・apiKeyPath などは、末尾が違うので対象外


def scan_text(text):
    """(行番号, 種類ID, 表示名, 値の長さ) の一覧と、環境変数の参照を使っていた項目の数。値は返さない。"""
    findings, env_refs = [], 0
    for n, line in enumerate(text.split("\n"), 1):
        claimed = []
        for kid, label, pat in KINDS:
            for m in pat.finditer(line):
                if any(m.start() < b and a < m.end() for a, b in claimed):
                    continue
                claimed.append((m.start(), m.end()))
                findings.append((n, kid, label, m.end() - m.start() if kid != "private-key" else 0))
        env_refs += sum(1 for m in ENV_FIELD_RE.finditer(line) if secret_like_name(m.group(1)))
        for m in FIELD_RE.finditer(line):
            name, val = m.group(1).lower(), m.group(2)
            if not secret_like_name(name):
                continue
            if is_env_reference(val):
                continue
            if looks_like_path(val) or any(p in val.lower() for p in PLACEHOLDERS):
                continue
            if any(a <= m.start(2) < b for a, b in claimed) or entropy(val) < MIN_ENTROPY:
                continue
            findings.append((n, "generic-secret-field", "「キー・トークン・パスワード」などの名前の項目に、平文の値", len(val)))
    return findings, env_refs


def default_locations(home):
    files = [os.path.join(home, *p.split("/")) for p in KNOWN_FILES]
    dirs = []
    roots = [os.path.join(home, *p.split("/")) for p in GLOBALSTORAGE]
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots += [os.path.join(appdata, "Code", "User", "globalStorage"), os.path.join(appdata, "Cursor", "User", "globalStorage")]
    for root in roots:
        if os.path.isdir(root):
            try:
                for name in sorted(os.listdir(root)):
                    if any(h in name.lower() for h in GLOBALSTORAGE_DIR_HINTS) and os.path.isdir(os.path.join(root, name)):
                        dirs.append(os.path.join(root, name))
            except OSError:
                pass
    return files, dirs, roots


def iter_files(path, max_bytes, depth=3):
    if os.path.isfile(path):
        yield path
        return
    base = path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d)) and d != ".git" and
                   root.rstrip(os.sep).count(os.sep) - base < depth]
        for name in files:
            full = os.path.join(root, name)
            if os.path.islink(full) or not (name.lower().endswith(SCAN_EXT) or name in SCAN_NAMES):
                continue
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            yield full


def perm_note(path):
    if os.name == "nt":
        return ""
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return ""
    return "他のユーザーが読める権限(%s)" % oct(mode) if mode & 0o044 else ""


def run(home, extra_paths=(), use_defaults=True, max_bytes=512_000):
    """(指摘のリスト, 確認した場所のリスト, エラーのリスト)。指摘に、秘密情報の値は含めない。"""
    results, checked, errors, seen = [], [], [], set()
    targets = []
    if use_defaults:
        files, dirs, roots = default_locations(home)
        for p in files:
            checked.append((p, os.path.isfile(p)))
            if os.path.isfile(p):
                targets.append(p)
        for r in roots:
            checked.append((r, os.path.isdir(r)))
        for d in dirs:
            checked.append((d, True))
            targets.extend(iter_files(d, max_bytes))
    for p in extra_paths:
        if not os.path.exists(p):
            errors.append("見つかりません: %s" % p)
            continue
        checked.append((p, True))
        targets.extend(iter_files(p, max_bytes))
    env_total = 0
    for path in targets:
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            errors.append("読み取りに失敗: %s: %s" % (path, e))
            continue
        findings, env_refs = scan_text(text)
        env_total += env_refs
        perm = perm_note(path) if findings else ""
        for n, kid, label, length in findings:
            results.append({"path": path, "line": n, "kind": kid, "label": label, "length": length, "perm": perm})
    return results, checked, errors, env_total, len(seen)


def to_sarif(results):
    return {"version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "ai_tool_config_secret_check", "rules": []}},
                      "results": [{"ruleId": "ai-tool-config-secret/" + r["kind"], "level": "warning",
                                   "message": {"text": "%s(%s)%s。値は出力しません。" % (
                                       r["label"], ("%d文字" % r["length"]) if r["length"] else "長さ不明",
                                       (" / " + r["perm"]) if r["perm"] else "")},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": r["path"].replace(os.sep, "/")},
                                                                       "region": {"startLine": r["line"]}}}],
                                   "properties": {"title": "AI開発ツールの設定ファイルに平文の秘密情報"}} for r in results]}]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--home", default=os.path.expanduser("~"), help="ホームフォルダ(既定: 自分のホーム)")
    ap.add_argument("--path", action="append", default=[], help="追加で調べるファイル/フォルダ(繰り返し指定可)")
    ap.add_argument("--no-default-locations", action="store_true", help="既知の場所を調べず、--path だけ調べる")
    ap.add_argument("--max-file-bytes", type=int, default=512_000)
    ap.add_argument("--out", default="", help="SARIFの出力先(値は含まない)")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    results, checked, errors, env_refs, nfiles = run(a.home, a.path, not a.no_default_locations, a.max_file_bytes)
    exist = [p for p, ok in checked if ok]
    print("確認した場所: %d 箇所のうち、存在したもの %d 箇所(読んだファイル %d 個)" % (len(checked), len(exist), nfiles))
    for p in exist:
        print("  存在: " + p)
    if not exist:
        print("  (既知の場所に、AI開発ツールの設定が見つかりませんでした。お使いの版の保存先が違う可能性があります。--path で指定できます)")
    print("-" * 60)
    for e in errors:
        print(e, file=sys.stderr)
    for r in results:
        print("  %s -> %s:%d  [%s]%s" % (r["label"], r["path"], r["line"],
                                         ("%d文字" % r["length"]) if r["length"] else "長さ不明",
                                         (" 警告: " + r["perm"]) if r["perm"] else ""))
    if results:
        print("\n計 %d 件。値は表示していません。" % len(results))
        print("対応: キーを、環境変数(設定ファイルでは ${変数名} の参照)やOSのキーストアに移し、設定ファイルからは消す。")
        print("      すでに他人に見られた・マルウェアに感染した可能性があれば、そのキーを失効して、発行し直す。")
        if any(r["perm"] for r in results):
            print("      権限が広いファイルは、`chmod 600 <ファイル>` で、自分だけが読めるようにする。")
    else:
        print("平文の秘密情報らしいものは見つかりませんでした(見逃しはあり得ます。限界は --help)。")
    if env_refs:
        print("環境変数の参照を使っている項目: %d 件(これは推奨の形です)" % env_refs)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(to_sarif(results), f, ensure_ascii=False, indent=2)
        print("SARIF: %s(値は含まれません)" % a.out)
    return 1 if results else (2 if errors else 0)


if __name__ == "__main__":
    sys.exit(main())
