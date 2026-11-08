#!/usr/bin/env python3
"""github_workflow_leak_check: CI/エージェントワークフローのイベントログを読み、R27
(「GitLost」: プライベートリポジトリの読み取り直後に、公開の出力先へ書き込む)相当の
パターンを確認する(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r27_agentic_workflow_private_data_public_write.yml`は、
    「同一run_id(同一の実行)の中で、プライベートリポジトリの読み取りと、公開の出力
    (Issueコメント・PRコメント・公開ページ等)への書き込みの両方が起きる」というパターンを
    検知対象にしている。Noma Securityが開示した「GitLost」(公開GitHub Issueの隠し指示が、
    GitHub Agentic Workflowsを操ってプライベートデータを公開流出させた)を模した探索的
    ヒューリスティック。
  - `verification-gates.md`の棚卸しで見つかったギャップ。ルール自体に「再利用可能なログ
    シグネチャは公開されておらず、本リポジトリ独自の構成」と明記されている。

対応するログ形式:
  - JSON Lines形式。各行は1つのGitHubイベント。`run_id`・`event_type`
    (`repo.content.read`/`actions.workflow_run`/`issue_comment.create`/
    `pull_request_comment.create`/`pages.publish`/`artifact.publish`)・
    `repository_visibility`(private読み取り側)・`output_visibility`(public書き込み側)を認識する。

安全のための制限:
  - **ログファイルを読むだけ**。GitHubへの書き込み・APIコールは一切しない。

使用例:
  python3 scripts/github_workflow_leak_check.py --log-path github_events.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass

# r27_agentic_workflow_private_data_public_write.yml の selection_private_read / selection_public_write
# と完全に同じ。
R27_PRIVATE_READ_EVENTS = {"repo.content.read", "actions.workflow_run"}
R27_PUBLIC_WRITE_EVENTS = {"issue_comment.create", "pull_request_comment.create", "pages.publish", "artifact.publish"}


@dataclass
class GhEvent:
    run_id: str
    event_type: str
    repository_visibility: str
    output_visibility: str
    line_no: int


def parse_jsonl_line(line: str, line_no: int) -> GhEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    run_id = obj.get("run_id")
    event_type = obj.get("event_type")
    if not isinstance(run_id, str) or not run_id or not isinstance(event_type, str) or not event_type:
        return None
    return GhEvent(
        run_id,
        event_type,
        str(obj.get("repository_visibility", "")),
        str(obj.get("output_visibility", "")),
        line_no,
    )


def scan_log(log_path: str) -> tuple[list[str], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    by_run: dict[str, list[GhEvent]] = defaultdict(list)
    for i, line in enumerate(lines, start=1):
        ev = parse_jsonl_line(line, i)
        if ev:
            by_run[ev.run_id].append(ev)

    findings = []
    for run_id, evs in by_run.items():
        has_private_read = any(
            e.event_type in R27_PRIVATE_READ_EVENTS and e.repository_visibility == "private" for e in evs
        )
        public_writes = [
            e for e in evs if e.event_type in R27_PUBLIC_WRITE_EVENTS and e.output_visibility == "public"
        ]
        if has_private_read and public_writes:
            for w in public_writes:
                findings.append(
                    "[R27] run_id=%s: プライベートリポジトリ読み取り後に公開出力(%s、行 %d)へ書き込み"
                    % (run_id, w.event_type, w.line_no)
                )

    return findings, len(lines), None


def print_report(findings: list[str], total_lines: int, log_path: str) -> None:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)
    if not findings:
        print("R27(GitLost: private読み取り→public書き込み)相当のパターンは見つかりませんでした。")
        return
    print("%d 件のパターンが見つかりました:\n" % len(findings))
    for f in findings:
        print("  %s" % f)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="GitHubイベントのログ(JSON Lines)")
    args = parser.parse_args()

    findings, total_lines, err = scan_log(args.log_path)
    if err:
        print(err, file=sys.stderr)
        return 2

    print_report(findings, total_lines, args.log_path)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
