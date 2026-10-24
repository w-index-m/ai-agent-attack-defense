#!/usr/bin/env python3
"""python_brotli_check: Pythonの`brotli`/`brotlicffi`パッケージが、CVE-2026-111497
(通称"Node2Shell"、PyPI側への波及が2026-10-22公開のGHSA-9v8h-qqgm-4m35で確認された、
Brotli展開処理の境界外書き込み。本リポジトリのR24参照)の対象になりうるかを確認する
(確認専用)。

背景:
  - 根本原因はBrotliデコーダの境界外書き込み(out-of-bounds write)。攻撃者が細工した
    Brotliデータを展開させることで、メモリリークまたは任意コード実行に繋がりうる。
  - 元々はNode.js本体の脆弱性として公開("Node2Shell")。2026-10-21、Node.js公式が
    22.23.4/24.22.1/26.12.1で修正(他9件のCVEとまとめて、計10件のうち4件がhigh)。
  - 2026-10-22、GitHub公式Security Advisory(GHSA-9v8h-qqgm-4m35、Critical評価)で、
    PyPIの`brotli`(1.0.3〜1.2.0が脆弱、1.2.1で修正)と`brotlicffi`(1.0.3〜1.2.0.xが脆弱、
    1.2.1.0で修正)への波及が確認された。
  - `requests`・`httpx`・`aiohttp`等の主要HTTPクライアントライブラリが、これらの
    パッケージが入っていれば自動的に読み込むため、直接`import brotli`していない
    アプリも間接的に影響を受けうる。
  - 2026-10-23時点で、このCVEが脆弱性DB側でPyPIパッケージに正しくマッピングされておらず、
    pip-audit/Dependabot/Safetyでは検出されない可能性がある(Aikido Securityの指摘)。
    本ツールは、この「検知されない可能性がある」というギャップを埋める目的で作成。

このツールが確認すること:
  - 実行中のPython環境(既定: このインタプリタ自身。`--python`で別のPython実行ファイルを
    指定可能)にインストールされている`Brotli`(PyPIパッケージ名、import名は`brotli`)・
    `brotlicffi`のバージョンを、`importlib.metadata`で読み取り、修正版と照合する。
  - ログ確認(任意、--log-path または --journalctl-unit): アプリケーションログから、
    R24のSigmaルールが探しているのと同じパターン——gunicorn/uwsgi等のworkerクラッシュ
    特有の行が、brotli関連の文脈の近くに現れていないかを確認する。**これは本リポジトリの
    他の検知ツールと同様、確認専用の参考情報であり、確証ではない**(R24自体が、ベンダー
    未公開の探索的ヒューリスティックである点に注意)。

安全のための制限:
  - **確認だけ**。パッケージの更新、コードの実行、ネットワークへの送信は一切しない。
  - 実行するのは、このホスト(または`--python`で指定したインタプリタ)のパッケージ
    メタデータの読み取りと、ログファイル/journalctlの読み取りだけ。

使い方:
    python3 scripts/python_brotli_check.py
    python3 scripts/python_brotli_check.py --out brotli_check.sarif
    python3 scripts/python_brotli_check.py --python /path/to/venv/bin/python3
    python3 scripts/python_brotli_check.py --log-path /var/log/myapp/gunicorn.log

標準ライブラリだけで動く(Python 3.8 以上。`importlib.metadata`は3.8で標準搭載)。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "python-brotli-check"

# GitHub Security Advisory GHSA-9v8h-qqgm-4m35(2026-10-22、Critical)に基づく修正版。
FIXED_VERSIONS = {
    "brotli": (1, 2, 1),       # PyPI配布名はBrotli。1.0.3〜1.2.0が脆弱。
    "brotlicffi": (1, 2, 1, 0),  # 1.0.3〜1.2.0.xが脆弱。
}

CVE_REFERENCE = (
    "CVE-2026-111497(通称Node2Shell、Brotliデコーダの境界外書き込み。PyPI側の影響は"
    "GHSA-9v8h-qqgm-4m35、Critical、2026-10-22公開。本リポジトリのR24参照): "
    "https://github.com/advisories/GHSA-9v8h-qqgm-4m35"
)

VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")

WORKER_CRASH_MARKERS = ["was sent SIGSEGV", "WORKER TIMEOUT", "DAMN ! worker", "Segmentation fault", "core dumped"]
BROTLI_CONTEXT_MARKERS = ["brotli", "Brotli", "Content-Encoding: br"]
LOG_CONTEXT_WINDOW = 3


def parse_version(v: str) -> tuple[int, ...]:
    m = VERSION_RE.match(v)
    if not m:
        return ()
    return tuple(int(g) for g in m.groups() if g is not None)


def check_package_local(pkg_import_name: str, pkg_dist_names: list[str]) -> tuple[str, str, str | None]:
    """このインタプリタ自身のimportlib.metadataで、インストール済みパッケージの
    バージョンを確認する(ネットワークアクセスなし)。"""
    try:
        import importlib.metadata as im
    except ImportError:
        return "medium", "importlib.metadataが使えません(Python 3.8未満)。", None

    version_str = None
    for dist_name in pkg_dist_names:
        try:
            version_str = im.version(dist_name)
            break
        except im.PackageNotFoundError:
            continue

    if version_str is None:
        return "info", "`%s`はこの環境にインストールされていません。" % pkg_import_name, None

    fixed = FIXED_VERSIONS[pkg_import_name]
    parsed = parse_version(version_str)
    if not parsed:
        return "medium", "`%s`のバージョン文字列を解釈できませんでした: %r" % (pkg_import_name, version_str), version_str

    if parsed < fixed:
        fixed_str = ".".join(str(x) for x in fixed)
        return (
            "high",
            "`%s` %s は修正版(%s)未満です。CVE-2026-111497の対象として、"
            "至急アップグレードしてください(`pip install -U %s`)。"
            % (pkg_import_name, version_str, fixed_str, pkg_dist_names[0]),
            version_str,
        )
    return "info", "`%s` %s は修正版以降に見えます。" % (pkg_import_name, version_str), version_str


def check_package_other_python(python_exe: str, pkg_import_name: str, pkg_dist_names: list[str]) -> tuple[str, str, str | None]:
    """--pythonで指定した別のインタプリタ(例: venv内)のパッケージを、サブプロセスで確認する。"""
    code = (
        "import importlib.metadata as im, sys\n"
        "names = %r\n"
        "for n in names:\n"
        "    try:\n"
        "        print(im.version(n)); sys.exit(0)\n"
        "    except im.PackageNotFoundError:\n"
        "        continue\n"
        "print('')\n"
    ) % pkg_dist_names
    try:
        out = subprocess.run([python_exe, "-c", code], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return "medium", "指定したPython実行ファイルが見つかりません: %s" % python_exe, None
    except Exception as e:
        return "medium", "%s の実行に失敗しました: %s" % (python_exe, e), None

    version_str = (out.stdout or "").strip()
    if not version_str:
        return "info", "`%s`は %s にインストールされていません。" % (pkg_import_name, python_exe), None

    fixed = FIXED_VERSIONS[pkg_import_name]
    parsed = parse_version(version_str)
    if not parsed:
        return "medium", "`%s`のバージョン文字列を解釈できませんでした: %r" % (pkg_import_name, version_str), version_str
    if parsed < fixed:
        fixed_str = ".".join(str(x) for x in fixed)
        return (
            "high",
            "%s の `%s` %s は修正版(%s)未満です。至急アップグレードしてください。"
            % (python_exe, pkg_import_name, version_str, fixed_str),
            version_str,
        )
    return "info", "%s の `%s` %s は修正版以降に見えます。" % (python_exe, pkg_import_name, version_str), version_str


def read_log_lines(log_path: str, journalctl_unit: str) -> tuple[list[str], str | None]:
    if journalctl_unit:
        try:
            out = subprocess.run(
                ["journalctl", "-u", journalctl_unit, "-n", "5000", "--no-pager"],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            return [], "journalctl コマンドが見つかりません。"
        except Exception as e:
            return [], "journalctl の実行に失敗しました: %s" % e
        if out.returncode != 0 and not out.stdout:
            return [], "journalctl -u %s の実行に失敗しました: %s" % (journalctl_unit, (out.stderr or "").strip()[:200])
        return out.stdout.splitlines(), None

    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            return f.readlines(), None
    except OSError as e:
        return [], "%s の読み取りに失敗しました: %s" % (log_path, e)


def scan_log_for_crash(lines: list[str]) -> list[tuple[int, str]]:
    hits = []
    n = len(lines)
    for i, ln in enumerate(lines):
        if not any(marker in ln for marker in WORKER_CRASH_MARKERS):
            continue
        lo, hi = max(0, i - LOG_CONTEXT_WINDOW), min(n, i + LOG_CONTEXT_WINDOW + 1)
        window = "".join(lines[lo:hi])
        if any(marker in window for marker in BROTLI_CONTEXT_MARKERS):
            hits.append((i + 1, ln.rstrip()))
    return hits


def worst(*severities: str) -> str:
    order = {"high": 3, "medium": 2, "info": 1}
    return max(severities, key=lambda s: order.get(s, 0))


def to_sarif(checks: list[tuple[str, str, str]], log_hits: list[tuple[int, str]] | None = None) -> dict:
    level_map = {"high": "error", "medium": "warning", "info": "note"}
    results = []
    for pkg, sev, msg in checks:
        results.append({
            "ruleId": "python-brotli-check-%s" % pkg,
            "level": level_map.get(sev, "warning"),
            "message": {"text": "%s %s" % (msg, CVE_REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "python:%s" % pkg}}}],
            "properties": {"severityLabel": sev},
        })
    for lineno, text in (log_hits or []):
        results.append({
            "ruleId": "python-brotli-worker-crash",
            "level": "warning",
            "message": {"text": "ログ%d行目: brotli文脈近くのworkerクラッシュ行が見つかりました(未確証の探索的ヒューリスティック): %s %s"
                                 % (lineno, text, CVE_REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "python:log"}, "region": {"startLine": lineno}}}],
            "properties": {"severityLabel": "medium"},
        })
    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {"name": DRIVER,
                                "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": datetime.now(timezone.utc).isoformat(timespec="seconds")}],
            "results": results,
        }],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="", help="SARIFの出力先(省略時は標準出力に要約のみ表示)")
    ap.add_argument("--python", default="", help="任意: このインタプリタではなく、指定したPython実行ファイル(例: venv内)のパッケージを確認する")
    ap.add_argument("--log-path", default="", help="任意: アプリケーションログからworkerクラッシュを探す")
    ap.add_argument("--journalctl-unit", default="", help="任意: --log-pathの代わりに、指定したsystemdユニットのjournalctlから探す")
    args = ap.parse_args()

    checks = []
    for pkg, dist_names in (("brotli", ["Brotli", "brotli"]), ("brotlicffi", ["brotlicffi"])):
        if args.python:
            sev, msg, _ = check_package_other_python(args.python, pkg, dist_names)
        else:
            sev, msg, _ = check_package_local(pkg, dist_names)
        checks.append((pkg, sev, msg))
        print("[%s] %s" % (sev, msg))

    log_hits: list[tuple[int, str]] = []
    if args.log_path or args.journalctl_unit:
        lines, log_err = read_log_lines(args.log_path, args.journalctl_unit)
        print()
        if log_err:
            print("ログ確認エラー: " + log_err, file=sys.stderr)
        else:
            source = ("journalctl -u %s" % args.journalctl_unit) if args.journalctl_unit else args.log_path
            log_hits = scan_log_for_crash(lines)
            print("ログ確認(%s、%d行、未確証の探索的ヒューリスティック):" % (source, len(lines)))
            if log_hits:
                print("  brotli文脈近くのworkerクラッシュ行が%d件見つかりました:" % len(log_hits))
                for lineno, text in log_hits[:10]:
                    print("    行%d: %s" % (lineno, text))
                print("  R24はベンダー未公開の探索的ヒューリスティックであり、ヒットは調査すべき")
                print("  手がかりに過ぎない(CVE-2026-111497固有の確証ではない)。")
            else:
                print("  該当する行は見つかりませんでした。")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(checks, log_hits), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
