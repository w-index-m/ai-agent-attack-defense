#!/usr/bin/env python3
"""php_version_check: PHPコア自体の重大な脆弱性チェーン「PHP2Shell」(CVE-2026-109618の
OOM破壊、CVE-2026-109619の古いグローバル状態に起因するUAF、各CVSS 9.2、2026-10-21公開)の
対象になりうるかを確認する(確認専用)。

背景:
  - 2026-10-21、PHP公式が緊急パッチをリリース。修正版: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12。
    7.4/8.0/8.1には最小限のソースバックポートが別途公開された(本リポジトリの R15 参照)。
  - 影響が最も大きいのはmod_php構成: アプリ側の認証チェックより先にリクエスト後処理が
    走るため、事前認証なしでトリガーされる。
  - 2026-10-22時点で、CISA KEVへの掲載は未確認。悪用は進行中とする報告はあるが、情報源間で
    評価にばらつきがある(watchTowr: 継続的な悪用試行を観測 / Tanium: 実害は限定的、
    大半は探索的プロービング)。

このツールが確認すること:
  - ローカルモード(既定): このホストの `php -v` の出力からバージョンを読み取り、
    PHP2Shellの修正版/脆弱版と照合する。
  - ログ確認(任意、--log-path または --journalctl-unit): php-fpmのメッセージログ
    (syslog/journal)から、R15のSigmaルールが検知するのと同じパターン——workerクラッシュ
    特有の行(`exited on signal 11`・`SIGSEGV`等)が、php-fpm文脈の近くに現れていないか
    を確認する。これは「workerがクラッシュしたこと」の確認であり、PHP2Shell固有の確証
    ではない点に注意(他の原因のクラッシュでも同じ形になりうる)。

安全のための制限:
  - **確認だけ**。php.iniの変更、PHPコードの実行、ネットワークへの送信は一切しない。
  - 実行するのは、このホストの `php -v` とログファイル/journalctlの読み取りだけ。
  - メモリ破壊・エクスプロイトの実行は一切行わない(確認専用)。

使い方:
    python3 scripts/php_version_check.py
    python3 scripts/php_version_check.py --out php_check.sarif
    python3 scripts/php_version_check.py --log-path /path/to/php-fpm.log
    python3 scripts/php_version_check.py --journalctl-unit php8.5-fpm

標準ライブラリだけで動く(Python 3.8 以上)。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "php-version-check"

# PHP公式アドバイザリ(2026-10-21)に基づく、ブランチごとの最初の修正版。
PHP2SHELL_FIRST_FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

CVE_REFERENCE = (
    "PHP2Shell(CVE-2026-109618のOOM破壊/CVE-2026-109619の古いグローバル状態UAF、"
    "各CVSS 9.2、2026-10-21公開、本リポジトリのR15参照): "
    "https://www.php2shell.com/ https://www.wiz.io/blog/php2shell-php-rce"
)

VERSION_RE = re.compile(r"PHP\s+(\d+)\.(\d+)\.(\d+)")

# R15のSigmaルール(r15_php2shell_worker_crash.yml)のselection_worker_crash /
# selection_fpm_contextと同じパターン。
WORKER_CRASH_MARKERS = ["exited on signal 11", "exited on signal 6", "SIGSEGV", "child exited with code"]
FPM_CONTEXT_MARKERS = ["php-fpm", "pool www"]
LOG_CONTEXT_WINDOW = 3


def assess_version(major: int, minor: int, patch: int) -> tuple[str, str]:
    branch = (major, minor)
    version_str = "%d.%d.%d" % (major, minor, patch)

    if branch in PHP2SHELL_FIRST_FIXED:
        fixed = PHP2SHELL_FIRST_FIXED[branch]
        if (major, minor, patch) < fixed:
            fixed_str = ".".join(str(x) for x in fixed)
            return (
                "high",
                "PHP %s は、このブランチの最初の修正版(%s)未満です。PHP2Shellの対象として、"
                "至急アップグレードしてください。" % (version_str, fixed_str),
            )
        return "info", "PHP %s は修正版以降に見えます。" % version_str

    if branch < (8, 2):
        return (
            "high",
            "PHP %s は8.2未満のブランチです。php2shell.com側の記載では『公式の修正版が無い』"
            "とされていますが、これはphp2shell.com自身の主張であり、php.net公式アドバイザリ"
            "での裏取りはできていません(本リポジトリのR15ルールも同じ留保を明記しています)。"
            "7.4/8.0/8.1向けの最小限のソースバックポートが別途公開されているため、"
            "php.net公式で確認してください。" % version_str,
        )

    return (
        "medium",
        "PHP %s は、このツールが持つデータより新しいブランチです(8.6以降等)。"
        "php.net公式アドバイザリで直接確認してください。" % version_str,
    )


def check_local() -> tuple[str, str, str | None]:
    try:
        out = subprocess.run(["php", "-v"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return "info", "このホストに `php` コマンドが見つかりません(PHP未インストール、またはPATH外)。", None
    except Exception as e:
        return "medium", "php -v の実行に失敗しました: %s" % e, None

    text = (out.stdout or "") + (out.stderr or "")
    m = VERSION_RE.search(text)
    if not m:
        return "medium", "php -v の出力からバージョンを読み取れませんでした: %r" % text.strip()[:200], None
    major, minor, patch = (int(x) for x in m.groups())
    severity, message = assess_version(major, minor, patch)
    first_line = text.strip().splitlines()[0] if text.strip() else None
    return severity, message, first_line


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
    """R15のSigmaルールと同じパターン(workerクラッシュ + php-fpm文脈)をログから探す。
    行単位の単純な文字列一致・前後数行の文脈確認のみ(構文解析はしない)。"""
    hits = []
    n = len(lines)
    for i, ln in enumerate(lines):
        if not any(marker in ln for marker in WORKER_CRASH_MARKERS):
            continue
        lo, hi = max(0, i - LOG_CONTEXT_WINDOW), min(n, i + LOG_CONTEXT_WINDOW + 1)
        window = "".join(lines[lo:hi])
        if any(marker in window for marker in FPM_CONTEXT_MARKERS):
            hits.append((i + 1, ln.rstrip()))
    return hits


def to_sarif(severity: str, message: str, version_text: str | None,
             log_hits: list[tuple[int, str]] | None = None) -> dict:
    level = {"high": "error", "medium": "warning", "info": "note"}.get(severity, "warning")
    results = [{
        "ruleId": "php-version-check",
        "level": level,
        "message": {"text": "%s %s" % (message, CVE_REFERENCE)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "php:version"}}}],
        "properties": {"severityLabel": severity, "versionText": version_text or ""},
    }]
    for lineno, text in (log_hits or []):
        results.append({
            "ruleId": "php-fpm-worker-crash",
            "level": "error",
            "message": {"text": "ログ%d行目: php-fpm workerクラッシュの行が見つかりました: %s %s"
                                 % (lineno, text, CVE_REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "php:log"}, "region": {"startLine": lineno}}}],
            "properties": {"severityLabel": "high"},
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
    ap.add_argument("--log-path", default="", help="任意: php-fpmのログファイル(syslog等)からworkerクラッシュを探す")
    ap.add_argument("--journalctl-unit", default="", help="任意: --log-pathの代わりに、指定したsystemdユニットのjournalctlから探す(例: php8.5-fpm)")
    args = ap.parse_args()

    severity, message, version_text = check_local()
    print("[%s] %s" % (severity, message))
    if version_text:
        print("バージョン文字列: %s" % version_text)

    log_hits: list[tuple[int, str]] = []
    if args.log_path or args.journalctl_unit:
        lines, log_err = read_log_lines(args.log_path, args.journalctl_unit)
        print()
        if log_err:
            print("ログ確認エラー: " + log_err, file=sys.stderr)
        else:
            source = ("journalctl -u %s" % args.journalctl_unit) if args.journalctl_unit else args.log_path
            log_hits = scan_log_for_crash(lines)
            print("ログ確認(%s、%d行):" % (source, len(lines)))
            if log_hits:
                print("  php-fpm workerクラッシュの行が%d件見つかりました:" % len(log_hits))
                for lineno, text in log_hits[:10]:
                    print("    行%d: %s" % (lineno, text))
                print("  これはworkerクラッシュを示すものであり、PHP2Shell固有の確証ではない点に注意"
                      "(他の原因のクラッシュでも同じ形になりうる)。")
            else:
                print("  workerクラッシュの行は見つからない、またはphp-fpm文脈の近くにはありませんでした。")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(severity, message, version_text, log_hits), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
