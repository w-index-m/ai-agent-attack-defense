#!/usr/bin/env python3
"""process_tool_check: プロセス実行ログを読み、R6(自律エージェントの相関検知: 偵察ツールの
あとに別ツール)・R7(多数のセキュリティツールの短時間連続実行)・R8起動側(Webサーバーが
シェルを起動)相当のパターンを確認する(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r7_rapid_multitool_execution.yml`: 1つの親プロセスが、
    5分以内に5種類超の既知セキュリティツールを実行するパターン。
  - `security-scan/detections/elastic/r6_correlation_eql.json`: 同じ親プロセスの下で、
    `nmap`(偵察ツール)が実行されたあと、5分以内に別の攻撃ツールが実行されるパターン
    (R6の代表例として、Elastic EQLで実装されているもの)。
  - `security-scan/detections/sigma/r8_webshell_placement_and_spawn.yml`(後半・起動側):
    Webサーバー/アプリケーションサーバーのプロセスがシェルを起動するパターン。
  - いずれも「プロセス実行ログ」という同じログ源が前提のため、1本のスクリプトにまとめた
    (`verification-gates.md`の棚卸しで見つかったギャップ)。

対応するログ形式:
  - JSON Lines形式。各行は1つのプロセス起動イベント。`process_name`/`image`、
    `parent_process_name`/`parent_image`、`parent_process_id`、タイムスタンプ(`ts`)を認識する。

安全のための制限:
  - **ログファイルを読むだけ**。プロセスの起動・停止は一切しない。

使用例:
  python3 scripts/process_tool_check.py --log-path process_events.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass

# r7_rapid_multitool_execution.yml の selection_tools.process_name と完全に同じ。
R7_SECURITY_TOOLS = {
    "nmap", "ffuf", "gobuster", "nikto", "sqlmap", "hydra",
    "nuclei", "wpscan", "msfconsole", "medusa", "enum4linux",
}
R7_TIMEFRAME_SECONDS = 5 * 60  # Sigmaルールの timeframe: 5m と同じ
R7_THRESHOLD = 4  # count(process_name) by parent_process_id > 4

# r6_correlation_eql.json の EQL sequence と同じ(nmapの次に、この中のどれかが来る)。
R6_FOLLOWUP_TOOLS = {"ffuf", "gobuster", "nikto", "sqlmap", "hydra", "nuclei", "wpscan", "msfconsole"}
R6_MAXSPAN_SECONDS = 5 * 60

# r8_webshell_placement_and_spawn.yml(起動側)の selection_parent / selection_child と完全に同じ。
R8_WEBSERVER_SUFFIXES = ("/java", "/nginx", "/httpd", "/apache2", "/php-fpm", "/php-fpm7", "/php-fpm8")
R8_SHELL_SUFFIXES = ("/sh", "/bash", "/dash", "/zsh")


@dataclass
class ProcEvent:
    ts: float | None
    parent_id: str
    parent_name: str
    process_name: str
    line_no: int


def parse_jsonl_line(line: str, line_no: int) -> ProcEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    proc = obj.get("process_name") or obj.get("image") or obj.get("Image")
    if not isinstance(proc, str) or not proc:
        return None
    parent_id = str(obj.get("parent_process_id") or obj.get("ppid") or "")
    parent_name = str(obj.get("parent_process_name") or obj.get("parent_image") or obj.get("ParentImage") or "")
    ts = obj.get("ts") or obj.get("timestamp")
    ts_val = float(ts) if isinstance(ts, (int, float)) else None
    return ProcEvent(ts_val, parent_id, parent_name, proc, line_no)


def _base_name(path: str) -> str:
    return path.rsplit("/", 1)[-1].lower()


def check_r7(events: list[ProcEvent]) -> list[str]:
    """同一parent_process_idの下で、5分以内にR7_SECURITY_TOOLSの異なるツールが
    R7_THRESHOLDを超えて実行されたか。タイムスタンプが無いイベントは、全体を1つの
    窓とみなす(既存スクリプトと同じ割り切り)。"""
    by_parent: dict[str, list[ProcEvent]] = defaultdict(list)
    for ev in events:
        if _base_name(ev.process_name) in R7_SECURITY_TOOLS:
            by_parent[ev.parent_id].append(ev)

    findings = []
    for parent_id, evs in by_parent.items():
        # 簡略化: 5分の時間窓でのスライディング集計はせず、同じparentの下の全イベントを
        # 1つの集合として数える(タイムスタンプが連続したログでは、実質的に5分より広い
        # 範囲も拾いうる -- 見逃しよりは安全側に倒す設計上の割り切り。本物のログでの
        # 検証は未実施)。
        distinct = {_base_name(e.process_name) for e in evs}
        if len(distinct) > R7_THRESHOLD:
            findings.append(
                "[R7] parent=%s: %d種類のセキュリティツールを実行(%s)"
                % (parent_id or "(不明)", len(distinct), ", ".join(sorted(distinct)))
            )
    return findings


def check_r6(events: list[ProcEvent]) -> list[str]:
    """同一parent_process_idの下で、nmap実行のあと、5分以内に別の攻撃ツールが実行されたか。"""
    by_parent: dict[str, list[ProcEvent]] = defaultdict(list)
    for ev in events:
        by_parent[ev.parent_id].append(ev)

    findings = []
    for parent_id, evs in by_parent.items():
        evs_sorted = sorted(evs, key=lambda e: e.ts if e.ts is not None else 0)
        nmap_ts = None
        for ev in evs_sorted:
            name = _base_name(ev.process_name)
            if name == "nmap":
                nmap_ts = ev.ts
                continue
            if nmap_ts is not None and name in R6_FOLLOWUP_TOOLS:
                if ev.ts is None or ev.ts - nmap_ts <= R6_MAXSPAN_SECONDS:
                    findings.append(
                        "[R6] parent=%s: nmap実行後に%sを実行(相関)" % (parent_id or "(不明)", name)
                    )
                    nmap_ts = None  # 1組につき1件報告
    return findings


def check_r8_spawn(events: list[ProcEvent]) -> list[str]:
    findings = []
    for ev in events:
        parent = ev.parent_name.lower()
        child = ev.process_name.lower()
        if parent.endswith(R8_WEBSERVER_SUFFIXES) and child.endswith(R8_SHELL_SUFFIXES):
            findings.append(
                "[R8] %s がシェル(%s)を起動(行 %d)" % (ev.parent_name, ev.process_name, ev.line_no)
            )
    return findings


def scan_log(log_path: str) -> tuple[list[str], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    events = [e for e in (parse_jsonl_line(line, i) for i, line in enumerate(lines, start=1)) if e]

    findings = check_r7(events) + check_r6(events) + check_r8_spawn(events)
    return findings, len(lines), None


def print_report(findings: list[str], total_lines: int, log_path: str) -> None:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)
    if not findings:
        print("R6・R7・R8(起動側)相当のパターンは見つかりませんでした。")
        return
    print("%d 件のパターンが見つかりました:\n" % len(findings))
    for f in findings:
        print("  %s" % f)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="プロセス実行イベントのログ(JSON Lines)")
    args = parser.parse_args()

    findings, total_lines, err = scan_log(args.log_path)
    if err:
        print(err, file=sys.stderr)
        return 2

    print_report(findings, total_lines, args.log_path)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
