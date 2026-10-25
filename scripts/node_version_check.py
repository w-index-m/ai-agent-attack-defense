#!/usr/bin/env python3
"""node_version_check: Node.js本体が、CVE-2026-111497(Brotliデコーダの境界外書き込み。
本リポジトリのR25参照)の対象になりうるかを確認する(確認専用)。

背景:
  - 根本原因はBrotliデコーダの境界外書き込み(out-of-bounds write)。攻撃者が細工した
    Brotliデータを展開させることで、メモリリークまたは任意コード実行に繋がりうる。
  - 2026-10-21、Node.js公式がセキュリティリリースでこのCVEを修正(22.23.4/24.22.1/
    26.12.1。同時に公開された他9件のCVEのうち4件がhigh評価)。これより古いメジャー
    ライン(20系以下)にはNode.js公式からの修正が存在しない(サポート終了のため)。
  - 2026-10-25時点で、複数の独立したセキュリティニュースサイトがこのNode.js公式
    リリースの内容を確認している(本リポジトリで裏取り済み)。
  - PyPIの`brotli`/`brotlicffi`への波及(R24、scripts/python_brotli_check.py)は
    GitHub公式Security Advisory(GHSA-9v8h-qqgm-4m35)で確認済みだが、Bun/Envoy Proxy/
    Istoへの波及を主張する情報は、本リポジトリでは単一ソースのため未確証として扱う
    (python-brotli-check-notes.mdの2026-10-25追記を参照)。本スクリプトはNode.js本体
    のみを対象とする。

このツールが確認すること:
  - 実行中のNode.js本体のバージョン(既定: `node --version`。`--node-path`で別の
    Node.js実行ファイルを指定可能)を取得し、メジャーラインごとの修正版と照合する。
  - ログ確認(任意、--log-path または --journalctl-unit): アプリケーションログから、
    R25のSigmaルールが探しているのと同じパターン——Node.jsプロセスの異常クラッシュ
    (SIGSEGV/core dumped等)が、brotli関連の文脈の近くに現れていないかを確認する。
    **これは確認専用の参考情報であり、確証ではない**(R24と同様、ベンダー未公開の
    探索的ヒューリスティックである点に注意)。

安全のための制限:
  - **確認だけ**。Node.jsの更新、コードの実行、ネットワークへの送信は一切しない。
  - 実行するのは、このホスト(または`--node-path`で指定した実行ファイル)のバージョン
    取得と、ログファイル/journalctlの読み取りだけ。

使い方:
    python3 scripts/node_version_check.py
    python3 scripts/node_version_check.py --out node_check.sarif
    python3 scripts/node_version_check.py --node-path /path/to/node
    python3 scripts/node_version_check.py --log-path /var/log/myapp/node.log

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
DRIVER = "node-version-check"

# Node.js公式の2026-10-21セキュリティリリースに基づく、メジャーラインごとの修正版。
# 複数の独立したセキュリティニュースサイトの報道で裏取り済み(2026-10-25時点)。
FIXED_VERSIONS = {
    22: (22, 23, 4),
    24: (24, 22, 1),
    26: (26, 12, 1),
}

CVE_REFERENCE = (
    "CVE-2026-111497(Brotliデコーダの境界外書き込み。Node.js公式2026-10-21リリースで"
    "修正。本リポジトリのR25参照)"
)

VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")

CRASH_MARKERS = ["SIGSEGV", "Segmentation fault", "core dumped", "FATAL ERROR", "signal 11"]
BROTLI_CONTEXT_MARKERS = ["brotli", "Brotli", "Content-Encoding: br", "zlib.js", "BrotliDecompress"]
LOG_CONTEXT_WINDOW = 3


def parse_version(v: str) -> tuple[int, int, int] | None:
    m = VERSION_RE.search(v)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def check_fixed(major: int, parsed: tuple[int, int, int]) -> tuple[str, str]:
    fixed = FIXED_VERSIONS.get(major)
    version_str = ".".join(str(x) for x in parsed)
    if fixed is None:
        return (
            "medium",
            "Node.js %s(メジャーライン%d系)は、Node.js公式がCVE-2026-111497向けの修正版を"
            "公開しているライン(22/24/26系)に含まれません。22/24/26系以降へのアップグレード、"
            "または別途Brotli関連の対策(リクエストのBrotli展開を無効化する等)を検討してください。"
            % (version_str, major),
        )
    if parsed < fixed:
        fixed_str = ".".join(str(x) for x in fixed)
        return (
            "high",
            "Node.js %s は、同じ%d系の修正版(%s)未満です。CVE-2026-111497の対象として、"
            "至急アップグレードしてください。" % (version_str, major, fixed_str),
        )
    return "info", "Node.js %s は修正版以降に見えます。" % version_str


def check_local() -> tuple[str, str, str | None]:
    return check_node_path("node")


def check_node_path(node_exe: str) -> tuple[str, str, str | None]:
    try:
        out = subprocess.run([node_exe, "--version"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return "medium", "Node.js実行ファイルが見つかりません: %s" % node_exe, None
    except Exception as e:
        return "medium", "%s の実行に失敗しました: %s" % (node_exe, e), None

    version_str = (out.stdout or "").strip()
    parsed = parse_version(version_str)
    if not parsed:
        return "medium", "Node.jsのバージョン文字列を解釈できませんでした: %r" % version_str, None

    sev, msg = check_fixed(parsed[0], parsed)
    return sev, msg, version_str


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
        if not any(marker in ln for marker in CRASH_MARKERS):
            continue
        lo, hi = max(0, i - LOG_CONTEXT_WINDOW), min(n, i + LOG_CONTEXT_WINDOW + 1)
        window = "".join(lines[lo:hi])
        if any(marker in window for marker in BROTLI_CONTEXT_MARKERS):
            hits.append((i + 1, ln.rstrip()))
    return hits


def to_sarif(sev: str, msg: str, version_str: str | None, log_hits: list[tuple[int, str]] | None = None) -> dict:
    level_map = {"high": "error", "medium": "warning", "info": "note"}
    results = [{
        "ruleId": "node-version-check",
        "level": level_map.get(sev, "warning"),
        "message": {"text": "%s %s" % (msg, CVE_REFERENCE)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "node:%s" % (version_str or "unknown")}}}],
        "properties": {"severityLabel": sev},
    }]
    for lineno, text in (log_hits or []):
        results.append({
            "ruleId": "node-brotli-worker-crash",
            "level": "warning",
            "message": {"text": "ログ%d行目: brotli文脈近くのNode.jsプロセスクラッシュ行が見つかりました"
                                 "(未確証の探索的ヒューリスティック): %s %s" % (lineno, text, CVE_REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "node:log"}, "region": {"startLine": lineno}}}],
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
    ap.add_argument("--node-path", default="", help="任意: PATH上の`node`ではなく、指定したNode.js実行ファイルを確認する")
    ap.add_argument("--log-path", default="", help="任意: アプリケーションログからworker/プロセスクラッシュを探す")
    ap.add_argument("--journalctl-unit", default="", help="任意: --log-pathの代わりに、指定したsystemdユニットのjournalctlから探す")
    args = ap.parse_args()

    if args.node_path:
        sev, msg, version_str = check_node_path(args.node_path)
    else:
        sev, msg, version_str = check_local()
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
                print("  brotli文脈近くのプロセスクラッシュ行が%d件見つかりました:" % len(log_hits))
                for lineno, text in log_hits[:10]:
                    print("    行%d: %s" % (lineno, text))
                print("  R25はベンダー未公開の探索的ヒューリスティックであり、ヒットは調査すべき")
                print("  手がかりに過ぎない(CVE-2026-111497固有の確証ではない)。")
            else:
                print("  該当する行は見つかりませんでした。")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(sev, msg, version_str, log_hits), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
