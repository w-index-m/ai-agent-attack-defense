#!/usr/bin/env python3
"""memory_poisoning_check: 混在ログ(ファイル書き込みイベント + セッション開始/egress
イベント)を読み、R32(エージェントの永続メモリ/設定ファイルへの汚染が、別セッションで
初めて発動する「二次/蓄積型IDPI」)相当のパターンを確認する(確認専用、読み取りのみ)。

背景:
  - R9(`proxy_egress_check.py`)が検知する間接プロンプトインジェクション(IDPI)は、
    「取得した外部コンテンツの指示に、同じセッション内で即座に従う」という即時型。
  - R32は、sqli-labの`second_order_sqli`/`stored_xss`と同じ構図を、DBやWebページでは
    なくAIコーディングエージェントの永続的な指示/メモリファイル(CLAUDE.md、AGENTS.md、
    `.claude/`/`.codex/`/`.cursor/`配下の設定、保存済みmemoryファイル等)に対して行う:
    ある時点のセッションが、汚染された指示をメモリファイルへ書き込む(その時点では何も
    起きない)。その後、**全く別のセッション**がハーネス起動時にそのファイルを自分自身の
    標準的な指示として読み込み、ユーザーが何も指示していないのに、最初の行動として
    許可リスト外への通信を行う。
  - 2026-11-09の会話で指摘された、本リポジトリ独自のギャップ分析(特定の実事件の
    モデル化ではない。`security-scan/detections/sigma/
    r32_persistent_agent_memory_second_order_injection.yml`参照)。

対応するログ形式:
  - JSON Lines形式。2種類のイベントが混在する前提:
    - ファイル書き込みイベント: `{"event": "memory_write", "ts": ..., "host": ...,
      "target_file": ..., "writer_process": ...}`
    - セッション開始イベント: `{"event": "session_start", "ts": ..., "host": ...,
      "session_id": ...}`
    - egressイベント: `{"event": "egress", "ts": ..., "host": ..., "session_id": ...,
      "dest_host": ...}`

判定方法:
  - `target_file`が既知のメモリ/設定ファイルパターン(CLAUDE.md・AGENTS.md・`.claude/`・
    `.codex/`・`.cursor/rules`・copilot-instructions.md・memory.json)に一致し、かつ
    `writer_process`が既知のエディタ(vim/nvim/nano/emacs/subl/code/pico)でない
    `memory_write`イベントを「疑わしい書き込み」とする。
  - 同一hostで、その書き込みより後に発生した`session_start`を探し、その
    `session_id`の最初の`egress`イベント(既定: セッション開始から600秒以内)の
    `dest_host`が許可リスト外であれば検知。

安全のための制限:
  - **ログファイルを読むだけ**。ネットワーク通信は一切しない。ログの改変もしない。

使用例:
  python3 scripts/memory_poisoning_check.py --log-path events.jsonl
  python3 scripts/memory_poisoning_check.py --log-path events.jsonl --allowlist-suffix example.com
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

MEMORY_PATH_SUBSTRINGS = (
    "CLAUDE.md",
    "AGENTS.md",
    ".claude/",
    ".codex/",
    ".cursor/rules",
    "copilot-instructions.md",
    "memory.json",
)

KNOWN_EDITOR_SUFFIXES = ("/vim", "/nvim", "/nano", "/emacs", "/subl", "/code", "/pico")

DEFAULT_TRIGGER_WINDOW_SECONDS = 600


@dataclass
class MemoryWrite:
    ts: float
    host: str
    target_file: str
    writer_process: str
    line_no: int


@dataclass
class SessionStart:
    ts: float
    host: str
    session_id: str


@dataclass
class EgressEvent:
    ts: float
    host: str
    session_id: str
    dest_host: str


def parse_jsonl_line(line: str, line_no: int):
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    event = obj.get("event")
    ts = obj.get("ts")
    host = obj.get("host")
    if not isinstance(event, str) or not isinstance(ts, (int, float)) or not isinstance(host, str):
        return None

    if event == "memory_write":
        target = obj.get("target_file")
        if not isinstance(target, str) or not target:
            return None
        writer = str(obj.get("writer_process", ""))
        return MemoryWrite(float(ts), host, target, writer, line_no)
    if event == "session_start":
        sid = obj.get("session_id")
        if not isinstance(sid, str) or not sid:
            return None
        return SessionStart(float(ts), host, sid)
    if event == "egress":
        sid = obj.get("session_id")
        dest = obj.get("dest_host")
        if not isinstance(sid, str) or not sid or not isinstance(dest, str) or not dest:
            return None
        return EgressEvent(float(ts), host, sid, dest)
    return None


def _is_memory_path(target_file: str) -> bool:
    return any(s in target_file for s in MEMORY_PATH_SUBSTRINGS)


def _is_known_editor(writer_process: str) -> bool:
    return writer_process.lower().endswith(tuple(s.lower() for s in KNOWN_EDITOR_SUFFIXES))


def _is_allowlisted(dest_host: str, allowlist_suffixes: list[str]) -> bool:
    dest_host = dest_host.lower().rstrip(".")
    return any(dest_host.endswith(s.lower()) for s in allowlist_suffixes)


@dataclass
class Finding:
    host: str
    target_file: str
    writer_process: str
    write_line_no: int
    session_id: str
    dest_host: str


def scan_log(
    log_path: str,
    trigger_window_seconds: int,
    allowlist_suffixes: list[str],
) -> tuple[list[Finding], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    writes: list[MemoryWrite] = []
    starts: list[SessionStart] = []
    egresses: list[EgressEvent] = []
    for i, line in enumerate(lines, start=1):
        ev = parse_jsonl_line(line, i)
        if isinstance(ev, MemoryWrite):
            writes.append(ev)
        elif isinstance(ev, SessionStart):
            starts.append(ev)
        elif isinstance(ev, EgressEvent):
            egresses.append(ev)

    suspicious_writes = [w for w in writes if _is_memory_path(w.target_file) and not _is_known_editor(w.writer_process)]

    # セッションごとの最初のegress(タイムスタンプ最小のもの)を求める。
    first_egress_by_session: dict[str, EgressEvent] = {}
    for eg in egresses:
        cur = first_egress_by_session.get(eg.session_id)
        if cur is None or eg.ts < cur.ts:
            first_egress_by_session[eg.session_id] = eg

    findings: list[Finding] = []
    for w in suspicious_writes:
        later_starts = [s for s in starts if s.host == w.host and s.ts > w.ts]
        for s in later_starts:
            first_eg = first_egress_by_session.get(s.session_id)
            if not first_eg:
                continue
            if first_eg.ts - s.ts > trigger_window_seconds:
                continue
            if _is_allowlisted(first_eg.dest_host, allowlist_suffixes):
                continue
            findings.append(Finding(w.host, w.target_file, w.writer_process, w.line_no, s.session_id, first_eg.dest_host))

    return findings, len(lines), None


def print_report(findings: list[Finding], total_lines: int, log_path: str) -> None:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)
    if not findings:
        print("R32(永続メモリ汚染による二次IDPI)相当のパターンは見つかりませんでした。")
        return
    print("%d 件のパターンが見つかりました:\n" % len(findings))
    for f in findings:
        print(
            "  [R32] %s: %s への疑わしい書き込み(行%d、writer=%s) -> "
            "後続セッション %s の初回egressが %s へ(許可リスト外)"
            % (f.host, f.target_file, f.write_line_no, f.writer_process or "(不明)", f.session_id, f.dest_host)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="混在ログ(JSON Lines)")
    parser.add_argument(
        "--trigger-window-seconds", type=int, default=DEFAULT_TRIGGER_WINDOW_SECONDS,
        help="セッション開始から最初のegressまでの許容秒数(既定: %d)" % DEFAULT_TRIGGER_WINDOW_SECONDS,
    )
    parser.add_argument(
        "--allowlist-suffix", action="append", default=[], metavar="SUFFIX",
        help="このドメインサフィックスへのegressは許可リスト内として除外する(repeatable)",
    )
    args = parser.parse_args()

    findings, total_lines, err = scan_log(args.log_path, args.trigger_window_seconds, args.allowlist_suffix)
    if err:
        print(err, file=sys.stderr)
        return 2

    print_report(findings, total_lines, args.log_path)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
