#!/usr/bin/env python3
"""patch_suggest: 診断結果(Semgrep / SARIF / Trivy)から、修正案(diff)を作る。**自動適用はしない**。

流れ: チェック(Semgrep/Trivy/gitleaks/netcheck) → 見つかった箇所の一覧(vuln_triage.html) →
このツールで「直し方の提案」を diff にする → **人が読んで確認してから** --apply で1件ずつ適用。

対象にする指摘の種類(安全側に絞っている):
  - Semgrep / SARIF(コードの指摘)  → 自前LLM(OpenAI互換エンドポイント)に、最小限の diff を作らせる。
  - Trivy の脆弱性(FixedVersion あり) → LLM を使わず、マニフェストのバージョン表記を書き換えるだけの
    決め打ちパッチ(依存ファイルに新しいコードを書かせるのは避ける)。
  - gitleaks(秘密情報)          → 対象外。「手動でローテーションしてください」と案内するだけ。
  - netcheck / zgrab2(露出の指摘)  → 対象外(コードではなく設定/運用の話のため)。

安全のための制限:
  - 生成するのは diff ファイルだけ。**適用(--apply)は 1 件ずつ、人の確認(y/N)が必須**。
  - 対象ファイルは、指定したリポジトリ直下の外に出られない(../ などのパス脱走を拒否)。
  - 実在しないファイル、サイズが大きすぎるファイルは対象外。
  - LLM への送信は、指定したエンドポイント**だけ**。生成された diff は、適用前に全文を表示する。
  - 秘密情報(gitleaks の検出値)は LLM に渡さない。
  - 小さいモデル(例: qwen2.5:1.5b)は、コード生成を間違えることがある。**必ず人が diff を読んでから適用する。**
  - 実行・適用の記録は patch_suggest.log に残す。

使い方:
    # 1) 提案(diff)を作るだけ(既定。何も変更しない)
    python3 scripts/patch_suggest.py results/ --repo . --llm-url http://localhost:11434/v1 --llm-model qwen2.5:1.5b

    # 2) 作った diff を、1件ずつ確認しながら適用する
    python3 scripts/patch_suggest.py results/ --repo . --apply

標準ライブラリだけで動く(Python 3.8 以上)。送信先は自分で指定したエンドポイントのみ。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, "patch_suggest.log")
MAX_FILE_BYTES = 200_000  # これより大きいファイルは対象外(文脈に収まらない)
CONTEXT_LINES = 12        # 指摘の行の前後、何行を LLM に見せるか


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def log(line):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (now(), line))
    except OSError:
        pass


# --- 診断結果の読み取り(vuln_triage.html の parseOne と同じ考え方) -------------

def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def semgrep_findings(data):
    out = []
    for r in (data or {}).get("results", []):
        e = r.get("extra", {})
        out.append({
            "tool": "semgrep", "rule_id": r.get("check_id", ""),
            "path": r.get("path", ""), "line": (r.get("start", {}) or {}).get("line"),
            "message": e.get("message", ""), "severity": str(e.get("severity", "")).upper(),
        })
    return out


def sarif_findings(data):
    out = []
    for run in (data or {}).get("runs", []):
        driver = (((run.get("tool") or {}).get("driver")) or {}).get("name", "SARIF")
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {}) or {}
            uri = (loc.get("artifactLocation") or {}).get("uri", "")
            line = (loc.get("region") or {}).get("startLine")
            msg = ((r.get("message") or {}).get("text")) or ""
            out.append({
                "tool": "sarif(%s)" % driver, "rule_id": r.get("ruleId", ""),
                "path": uri, "line": line, "message": msg, "severity": r.get("level", ""),
            })
    return out


def trivy_fixable(data):
    """FixedVersion がある脆弱性だけ。コードを書かせず、バージョン表記の置き換えに使う。"""
    out = []
    for res in (data or {}).get("Results", []):
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion", "")
            if not fixed:
                continue
            out.append({
                "target": target, "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""), "fixed": fixed,
                "id": v.get("VulnerabilityID", ""),
            })
    return out


def collect(results_dir):
    code_findings, trivy_items, n_secrets = [], [], 0
    sp = os.path.join(results_dir, "semgrep.json")
    if os.path.exists(sp):
        code_findings += semgrep_findings(load(sp))
    tp = os.path.join(results_dir, "trivy.json")
    if os.path.exists(tp):
        trivy_items += trivy_fixable(load(tp))
    gp = os.path.join(results_dir, "gitleaks.json")
    if os.path.exists(gp):
        gl = load(gp)
        n_secrets = len(gl) if isinstance(gl, list) else 0
    for fn in os.listdir(results_dir) if os.path.isdir(results_dir) else []:
        if fn.lower().endswith(".sarif") or fn.lower().endswith(".sarif.json"):
            d = load(os.path.join(results_dir, fn))
            if d and "runs" in (d or {}):
                code_findings += sarif_findings(d)
    return code_findings, trivy_items, n_secrets


# --- 安全な範囲内でのファイル読み書き -----------------------------------------

def safe_path(repo_root, rel):
    """リポジトリ直下の外に出られないようにする。範囲外・不在なら None。"""
    if not rel:
        return None
    full = os.path.normpath(os.path.join(repo_root, rel))
    root = os.path.normpath(repo_root)
    if full != root and not full.startswith(root + os.sep):
        return None
    if not os.path.isfile(full):
        return None
    try:
        if os.path.getsize(full) > MAX_FILE_BYTES:
            return None
    except OSError:
        return None
    return full


def read_context(full_path, line, span=CONTEXT_LINES):
    with open(full_path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    if not line:
        line = 1
    lo = max(1, line - span)
    hi = min(len(lines), line + span)
    out = []
    for i in range(lo, hi + 1):
        marker = ">> " if i == line else "   "
        out.append("%s%4d| %s" % (marker, i, lines[i - 1] if i - 1 < len(lines) else ""))
    return "\n".join(out), lo, hi


# --- 自前LLM呼び出し(OpenAI互換) ----------------------------------------------

def ask_llm(base_url, model, api_key, system_hint, user_prompt, timeout=120):
    url = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": model, "stream": False, "temperature": 0.1, "max_tokens": 700,
        "messages": [{"role": "user", "content": system_hint}, {"role": "user", "content": user_prompt}],
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        j = json.loads(r.read().decode("utf-8"))
    choices = j.get("choices") or []
    if not choices:
        return ""
    msg = choices[0].get("message") or {}
    return msg.get("content") or ""


DIFF_FENCE = re.compile(r"```(?:diff|patch)?\s*\n(.*?)```", re.S)


def extract_diff(text):
    m = DIFF_FENCE.search(text or "")
    body = m.group(1) if m else (text or "")
    body = body.strip("\n")
    if "--- " not in body or "+++ " not in body:
        return None
    return body + "\n"


def propose_code_patch(repo_root, finding, base_url, model, api_key):
    full = safe_path(repo_root, finding["path"])
    if not full:
        return None, "対象外(ファイルが無い/範囲外/大きすぎる): %s" % finding["path"]
    ctx, lo, hi = read_context(full, finding.get("line"))
    rel = os.path.relpath(full, repo_root)
    hint = (
        "あなたはセキュリティ修正の提案だけを行うアシスタントです。"
        "与えられた指摘1件だけを直す、最小限の unified diff を1つ作ってください。"
        "新しい攻撃手法やエクスプロイトは書かないでください。"
        "出力は ```diff で始まるコードブロックのみとし、説明文は書かないでください。"
        "diff のパスは '--- a/%s' と '+++ b/%s' にしてください。" % (rel, rel)
    )
    prompt = (
        "指摘: [%s] %s\nルール: %s\nファイル: %s (%d〜%d行目を表示。>> が該当行)\n\n%s"
        % (finding.get("severity", ""), finding.get("message", ""), finding.get("rule_id", ""),
           rel, lo, hi, ctx)
    )
    try:
        out = ask_llm(base_url, model, api_key, hint, prompt)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return None, "LLM呼び出しに失敗: %s" % e
    diff = extract_diff(out)
    if not diff:
        return None, "LLM の応答から diff を取り出せませんでした(モデルの出力を確認してください)。"
    return diff, None


def propose_version_bump(repo_root, item):
    """マニフェストの中の installed バージョン表記を fixed に書き換えるだけの、決め打ちパッチ。
    git apply が確実に当てられるよう、変更行の前後に文脈行を 2 行ずつ含める
    (文脈 0 行の diff は、git apply が探索に失敗することがあるため)。"""
    full = safe_path(repo_root, item["target"])
    if not full:
        return None, "対象外(マニフェストが無い/範囲外): %s" % item["target"]
    with open(full, encoding="utf-8", errors="replace") as f:
        src = f.read()
    pkg, inst, fixed = item["pkg"], item["installed"], item["fixed"]
    pattern = re.compile(re.escape(pkg) + r"([=<>~! ]+)" + re.escape(inst))
    if not pattern.search(src):
        return None, "マニフェスト内に %s==%s の表記が見つかりませんでした(手動確認が必要)。" % (pkg, inst)
    new_src = pattern.sub(lambda m: pkg + m.group(1) + fixed, src, count=1)
    rel = os.path.relpath(full, repo_root)
    old_lines, new_lines = src.splitlines(), new_src.splitlines()
    changed = [i for i, (o, n) in enumerate(zip(old_lines, new_lines)) if o != n]
    if not changed:
        return None, "バージョン表記の置き換え後、変更点がありませんでした。"
    i = changed[0]
    ctx = 2
    lo, hi = max(0, i - ctx), min(len(old_lines), i + ctx + 1)
    hunk = []
    for k in range(lo, i):
        hunk.append(" " + old_lines[k])
    hunk.append("-" + old_lines[i])
    hunk.append("+" + new_lines[i])
    for k in range(i + 1, hi):
        hunk.append(" " + old_lines[k])
    old_count, new_count = (hi - lo), (hi - lo)
    header = "@@ -%d,%d +%d,%d @@" % (lo + 1, old_count, lo + 1, new_count)
    diff_lines = ["--- a/%s" % rel, "+++ b/%s" % rel, header] + hunk
    return "\n".join(diff_lines) + "\n", None


# --- 適用(1件ずつ、人の確認が必須) ---------------------------------------------

def apply_patch(repo_root, patch_path):
    print("\n----- %s -----" % os.path.basename(patch_path))
    with open(patch_path, encoding="utf-8") as f:
        print(f.read())
    try:
        ans = input("この diff を適用しますか？ [y/N]: ").strip().lower()
    except EOFError:
        ans = ""
    if ans != "y":
        print("  → 適用しませんでした。")
        log("skip apply=%s" % patch_path)
        return False
    check = subprocess.run(["git", "apply", "--check", patch_path], cwd=repo_root, capture_output=True, text=True)
    if check.returncode != 0:
        print("  → 適用できませんでした(git apply --check が失敗): %s" % check.stderr.strip())
        log("apply-check-failed %s %s" % (patch_path, check.stderr.strip().replace("\n", " ")))
        return False
    r = subprocess.run(["git", "apply", patch_path], cwd=repo_root, capture_output=True, text=True)
    if r.returncode != 0:
        print("  → 適用に失敗しました: %s" % r.stderr.strip())
        log("apply-failed %s %s" % (patch_path, r.stderr.strip().replace("\n", " ")))
        return False
    print("  → 適用しました。差分を確認し、必ずテストを実行してください。")
    log("applied %s" % patch_path)
    return True


def main():
    ap = argparse.ArgumentParser(description="診断結果から修正案(diff)を作る。自動適用はしない。")
    ap.add_argument("results_dir", help="semgrep.json / trivy.json / gitleaks.json / *.sarif のあるフォルダ")
    ap.add_argument("--repo", default=".", help="対象のリポジトリのルート(既定: カレントディレクトリ)")
    ap.add_argument("--out", default="patches", help="diff の出力先フォルダ(既定: patches/)")
    ap.add_argument("--llm-url", default="http://localhost:11434/v1", help="OpenAI互換エンドポイント")
    ap.add_argument("--llm-model", default="qwen2.5:1.5b", help="モデル名")
    ap.add_argument("--llm-key", default="", help="APIキー(ローカルは空でよい)")
    ap.add_argument("--max", type=int, default=10, help="LLMに送る指摘の上限件数(既定10。多いと時間がかかる)")
    ap.add_argument("--apply", action="store_true", help="作成済みの diff(--out のフォルダ)を、1件ずつ確認して適用する")
    a = ap.parse_args()

    repo_root = os.path.abspath(a.repo)
    out_dir = os.path.abspath(a.out)

    if a.apply:
        if not os.path.isdir(out_dir):
            print("適用する diff がありません: %s" % out_dir, file=sys.stderr)
            return 1
        patches = sorted(p for p in os.listdir(out_dir) if p.endswith(".patch"))
        if not patches:
            print("適用する diff が見つかりませんでした。", file=sys.stderr)
            return 1
        applied = 0
        for p in patches:
            if apply_patch(repo_root, os.path.join(out_dir, p)):
                applied += 1
        print("\n%d / %d 件を適用しました。" % (applied, len(patches)))
        return 0

    if not os.path.isdir(a.results_dir):
        print("診断結果のフォルダが見つかりません: %s" % a.results_dir, file=sys.stderr)
        return 2
    code_findings, trivy_items, n_secrets = collect(a.results_dir)
    os.makedirs(out_dir, exist_ok=True)
    log("開始 results=%s repo=%s" % (a.results_dir, repo_root))

    made, skipped = 0, []

    for item in trivy_items:
        diff, err = propose_version_bump(repo_root, item)
        if err:
            skipped.append("[trivy] %s %s: %s" % (item["pkg"], item["id"], err))
            continue
        path = os.path.join(out_dir, "trivy_%s_%s.patch" % (item["pkg"].replace("/", "_"), item["id"]))
        with open(path, "w", encoding="utf-8") as f:
            f.write(diff)
        made += 1
        print("作成: %s (決め打ち。バージョン表記を %s → %s に書き換えるだけ)" % (path, item["installed"], item["fixed"]))

    llm_targets = code_findings[: a.max]
    if len(code_findings) > a.max:
        skipped.append("Semgrep/SARIF の指摘が多いため、先頭 %d 件だけ LLM に送りました(--max で変更可)。" % a.max)
    for i, f in enumerate(llm_targets):
        diff, err = propose_code_patch(repo_root, f, a.llm_url, a.llm_model, a.llm_key)
        if err:
            skipped.append("[%s] %s:%s %s" % (f["tool"], f["path"], f.get("line"), err))
            continue
        base = re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.basename(f["path"]) or "file")
        path = os.path.join(out_dir, "%s_%d_%s.patch" % (f["tool"].split("(")[0], i, base))
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(diff)
        made += 1
        print("作成: %s ← [%s] %s" % (path, f.get("severity", ""), f.get("message", "")[:60]))

    if n_secrets:
        print("\n⚠ gitleaks が %d 件の秘密情報を検出していますが、対象外です。直ちにローテーション(無効化して作り直す)してください。自動での修正は行いません。" % n_secrets)

    print("\n%d 件の diff を %s に作成しました。" % (made, out_dir))
    if skipped:
        print("対象外/失敗: %d 件" % len(skipped))
        for s in skipped:
            print("  - " + s)
    print("\n次の手順: diff の中身を読んで確認し、問題なければ")
    print("  python3 %s %s --repo %s --apply" % (os.path.basename(__file__), a.results_dir, a.repo))
    print("で、1件ずつ確認しながら適用してください。小さいモデルの提案は間違っていることがあります。")
    log("完了 made=%d skipped=%d" % (made, len(skipped)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
