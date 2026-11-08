#!/usr/bin/env python3
"""file_event_check: ファイル作成/変更イベントのログを読み、R5(cron/systemd永続化の新規作成)・
R8設置側(Webルート配下への実行可能コンテンツの書き込み)・R20(Markdownファイルの散発書き込み)・
R28(エディタ拡張機能によるSSH鍵の作成)相当のパターンを確認する(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r5_persistence_cron_systemd.yml`: cron設定・systemdの
    timer/serviceユニットへの書き込みを見る。
  - `security-scan/detections/sigma/r8_webshell_placement_and_spawn.yml`(前半・設置側):
    Webルート配下への`.jsp`/`.war`/`.php`等の実行可能コンテンツの書き込みを見る
    (dpkg/rpm等の正規デプロイツールは除外)。
  - `security-scan/detections/sigma/r20_agent_markdown_handoff_burst.yml`(2026-11-08追加):
    Unit 42が報告した「エージェント間のMarkdown経由の情報受け渡し」を模した探索的ヒューリスティック。
    1つのプロセスが、既知のドキュメントパス以外で、複数の異なるディレクトリに複数の異なる.md
    ファイルを、短時間(既定600秒)に書き込むパターン。**ルール自体が「二次情報源からの推測で、
    確認済みのシグネチャではない」と明記**。
  - `security-scan/detections/sigma/r28_ide_extension_ssh_persistence.yml`(2026-11-08追加):
    改ざんされたCursor拡張機能の事例を模した探索的ヒューリスティック。エディタ/拡張機能ホストの
    プロセスが、SSH鍵や`authorized_keys`を作成・変更するパターン。**こちらも二次情報源からの
    推測で、特定キャンペーンのシグネチャではなく一般的な技法への behavioral proxy と明記**。
  - `verification-gates.md`の棚卸しで見つかったギャップ。どれも「ファイル書き込みイベント」
    という同じログ源(auditd file_event等)が前提のため、1本のスクリプトにまとめた。

対応するログ形式:
  - JSON Lines形式。各行は1つのファイル書き込みイベント。`target_file`/`path`のいずれかと、
    `process_name`/`image`・`parent_process_name`・`ts`(任意)・`process_guid`/`host`(任意、
    R20の集計キー)を認識する。

安全のための制限:
  - **ログファイルを読むだけ**。ファイルの作成・変更は一切しない。

使用例:
  python3 scripts/file_event_check.py --log-path file_events.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass

# r5_persistence_cron_systemd.yml の selection_paths / selection_unit と完全に同じ。
R5_PATH_PREFIXES = ("/etc/cron.", "/var/spool/cron/", "/etc/systemd/system/", "/etc/crontab")
R5_PATH_SUFFIXES = (".timer", ".service", "crontab")

# r8_webshell_placement_and_spawn.yml(設置側)の selection_root / selection_ext / filter と完全に同じ。
R8_WEBROOT_SUBSTRINGS = ("/var/www/", "/usr/share/nginx/", "/webapps/", "/htdocs/", "/wwwroot/")
R8_EXECUTABLE_SUFFIXES = (".jsp", ".jspx", ".war", ".php", ".phtml", ".aspx", ".ashx")
R8_DEPLOY_TOOLING_SUFFIXES = ("/dpkg", "/rpm", "/yum", "/dnf", "/apt", "/apt-get")

# r20_agent_markdown_handoff_burst.yml の filter_known_doc_paths と完全に同じ。
R20_KNOWN_DOC_PATH_SUBSTRINGS = (
    "/docs/", "/wiki/", "/.git/", "README", "CHANGELOG", "node_modules/", "site-packages/",
)
# Sigmaルールのコメントが挙げる例(N=4超・M=2超)をそのまま既定値に採用。時間窓は「5-10分」の中間。
R20_WINDOW_SECONDS = 600
R20_MIN_DISTINCT_FILES = 4
R20_MIN_DISTINCT_DIRS = 2

# r28_ide_extension_ssh_persistence.yml の selection_parent / selection_target と完全に同じ。
R28_EDITOR_PARENT_SUBSTRINGS = ("Cursor", "Code - Insiders", "code", "extensionHost")
R28_SSH_TARGET_SUBSTRINGS = ("/.ssh/authorized_keys", "/.ssh/id_")


@dataclass
class FileEvent:
    target_file: str
    process_name: str
    parent_process_name: str
    ts: float | None
    group_key: str  # R20の集計キー(process_guidまたはhost、無ければprocess_name)
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
    process_name = obj.get("process_name") or obj.get("image") or obj.get("Image") or ""
    parent_process_name = (
        obj.get("parent_process_name") or obj.get("parent_image") or obj.get("ParentImage") or ""
    )
    ts = obj.get("ts") or obj.get("timestamp")
    ts_val = float(ts) if isinstance(ts, (int, float)) else None
    group_key = str(obj.get("process_guid") or obj.get("host") or process_name or "")
    return FileEvent(target, str(process_name), str(parent_process_name), ts_val, group_key, line_no)


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


def _matches_r28(ev: FileEvent) -> bool:
    if not any(s in ev.parent_process_name for s in R28_EDITOR_PARENT_SUBSTRINGS):
        return False
    if ev.target_file.endswith("authorized_keys"):
        return True
    return any(s in ev.target_file for s in R28_SSH_TARGET_SUBSTRINGS)


def _is_r20_candidate(target_file: str) -> bool:
    if not target_file.endswith(".md"):
        return False
    return not any(s in target_file for s in R20_KNOWN_DOC_PATH_SUBSTRINGS)


def check_r20(events: list[FileEvent]) -> list[str]:
    """同一group_keyの下で、既知ドキュメントパス以外の.mdファイルが、複数の異なる
    ディレクトリに、既定10分以内に散発的に書き込まれたか。タイムスタンプが無ければ
    全体を1つの窓とみなす(他のスクリプトと同じ割り切り)。"""
    by_group: dict[str, list[FileEvent]] = defaultdict(list)
    for ev in events:
        if _is_r20_candidate(ev.target_file):
            by_group[ev.group_key].append(ev)

    findings = []
    for group_key, evs in by_group.items():
        # 簡略化: 窓を跨ぐ場合も、見逃しを避けるため全体を1つの集合として数える
        # (process_tool_check.pyのR7と同じ割り切り。本物のログでの検証は未実施)。
        files = {e.target_file for e in evs}
        dirs = {e.target_file.rsplit("/", 1)[0] for e in evs}
        if len(files) > R20_MIN_DISTINCT_FILES and len(dirs) > R20_MIN_DISTINCT_DIRS:
            findings.append(
                "[R20] group=%s: %d個の.mdファイルを%d個の異なるディレクトリに散発書き込み(%s)"
                % (group_key or "(不明)", len(files), len(dirs), ", ".join(sorted(files)[:5]) + ("..." if len(files) > 5 else ""))
            )
    return findings


def scan_log(log_path: str) -> tuple[list[tuple[FileEvent, str]], list[str], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    hits: list[tuple[FileEvent, str]] = []
    events: list[FileEvent] = []
    for i, line in enumerate(lines, start=1):
        ev = parse_jsonl_line(line, i)
        if not ev:
            continue
        events.append(ev)
        if _matches_r5(ev):
            hits.append((ev, "R5"))
        elif _matches_r8_placement(ev):
            hits.append((ev, "R8"))
        if _matches_r28(ev):
            hits.append((ev, "R28"))

    r20_findings = check_r20(events)
    return hits, r20_findings, len(lines), None


_RULE_LABELS = {
    "R5": "永続化の新規作成(cron / systemd timer)",
    "R8": "Webシェル設置(Webルート配下への実行可能コンテンツ書き込み)",
    "R28": "エディタ拡張機能によるSSH鍵の作成/authorized_keysの変更",
}


def print_report(
    hits: list[tuple[FileEvent, str]], r20_findings: list[str], total_lines: int, log_path: str
) -> list:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)
    all_hits = list(hits) + list(r20_findings)
    if not all_hits:
        print("R5・R8(設置側)・R20・R28相当のパターンは見つかりませんでした。")
        return all_hits

    if hits:
        print("%d 件のファイル書き込みが一致しました:\n" % len(hits))
        for ev, rule in hits:
            print(
                "  [%s] %s -> %s (行 %d、process=%s)"
                % (rule, _RULE_LABELS[rule], ev.target_file, ev.line_no, ev.process_name or "(不明)")
            )
    for f in r20_findings:
        print("  %s" % f)
    return all_hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="ファイル書き込みイベントのログ(JSON Lines)")
    args = parser.parse_args()

    hits, r20_findings, total_lines, err = scan_log(args.log_path)
    if err:
        print(err, file=sys.stderr)
        return 2

    all_hits = print_report(hits, r20_findings, total_lines, args.log_path)
    return 1 if all_hits else 0


if __name__ == "__main__":
    sys.exit(main())
