#!/usr/bin/env python3
"""file_event_check: ファイル作成/変更イベントのログを読み、R5(cron/systemd永続化の新規作成)・
R8設置側(Webルート配下への実行可能コンテンツの書き込み)相当のパターンを確認する
(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r5_persistence_cron_systemd.yml`: cron設定・systemdの
    timer/serviceユニットへの書き込みを見る。
  - `security-scan/detections/sigma/r8_webshell_placement_and_spawn.yml`(前半・設置側):
    Webルート配下への`.jsp`/`.war`/`.php`等の実行可能コンテンツの書き込みを見る
    (dpkg/rpm等の正規デプロイツールは除外)。
  - `verification-gates.md`の棚卸しで見つかったギャップ。どちらも「ファイル書き込みイベント」
    という同じログ源(auditd file_event等)が前提のため、1本のスクリプトにまとめた。

対応するログ形式:
  - JSON Lines形式。各行は1つのファイル書き込みイベント。`target_file`/`path`のいずれかと、
    `process_name`/`image`のいずれか(任意)を認識する。

安全のための制限:
  - **ログファイルを読むだけ**。ファイルの作成・変更は一切しない。

使用例:
  python3 scripts/file_event_check.py --log-path file_events.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

# r5_persistence_cron_systemd.yml の selection_paths / selection_unit と完全に同じ。
R5_PATH_PREFIXES = ("/etc/cron.", "/var/spool/cron/", "/etc/systemd/system/", "/etc/crontab")
R5_PATH_SUFFIXES = (".timer", ".service", "crontab")

# r8_webshell_placement_and_spawn.yml(設置側)の selection_root / selection_ext / filter と完全に同じ。
R8_WEBROOT_SUBSTRINGS = ("/var/www/", "/usr/share/nginx/", "/webapps/", "/htdocs/", "/wwwroot/")
R8_EXECUTABLE_SUFFIXES = (".jsp", ".jspx", ".war", ".php", ".phtml", ".aspx", ".ashx")
R8_DEPLOY_TOOLING_SUFFIXES = ("/dpkg", "/rpm", "/yum", "/dnf", "/apt", "/apt-get")


@dataclass
class FileEvent:
    target_file: str
    process_name: str
    line_no: int


def parse_jsonl_line(line: str, line_no: int) -> FileEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    target = obj.get("target_file") or obj.get("path") or obj.get("TargetFilename")
    if not isinstance(target, str) or not target:
        return None
    process_name = (
        obj.get("process_name") or obj.get("image") or obj.get("Image") or ""
    )
    return FileEvent(target, str(process_name), line_no)


def _matches_r5(ev: FileEvent) -> bool:
    return ev.target_file.startswith(R5_PATH_PREFIXES) or ev.target_file.endswith(R5_PATH_SUFFIXES)


def _matches_r8_placement(ev: FileEvent) -> bool:
    if not any(s in ev.target_file for s in R8_WEBROOT_SUBSTRINGS):
        return False
    if not ev.target_file.endswith(R8_EXECUTABLE_SUFFIXES):
        return False
    if ev.process_name.endswith(R8_DEPLOY_TOOLING_SUFFIXES):
        return False
    return True


def scan_log(log_path: str) -> tuple[list[tuple[FileEvent, str]], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    hits: list[tuple[FileEvent, str]] = []
    for i, line in enumerate(lines, start=1):
        ev = parse_jsonl_line(line, i)
        if not ev:
            continue
        if _matches_r5(ev):
            hits.append((ev, "R5"))
        elif _matches_r8_placement(ev):
            hits.append((ev, "R8"))

    return hits, len(lines), None


_RULE_LABELS = {
    "R5": "永続化の新規作成(cron / systemd timer)",
    "R8": "Webシェル設置(Webルート配下への実行可能コンテンツ書き込み)",
}


def print_report(hits: list[tuple[FileEvent, str]], total_lines: int, log_path: str) -> None:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)
    if not hits:
        print("R5(永続化)・R8(Webシェル設置)相当のパターンは見つかりませんでした。")
        return

    print("%d 件のファイル書き込みが一致しました:\n" % len(hits))
    for ev, rule in hits:
        print(
            "  [%s] %s -> %s (行 %d、process=%s)"
            % (rule, _RULE_LABELS[rule], ev.target_file, ev.line_no, ev.process_name or "(不明)")
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="ファイル書き込みイベントのログ(JSON Lines)")
    args = parser.parse_args()

    hits, total_lines, err = scan_log(args.log_path)
    if err:
        print(err, file=sys.stderr)
        return 2

    print_report(hits, total_lines, args.log_path)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
