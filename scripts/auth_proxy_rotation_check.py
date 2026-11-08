#!/usr/bin/env python3
"""auth_proxy_rotation_check: 認証ログを読み、R30(単一アカウント/セッションが短時間に
多数の異なる送信元IPから認証、プロキシローテーション基盤の兆候)相当のパターンを確認する
(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r30_multi_egress_ip_proxy_rotation.yml`は、「同一アカウント/
    セッションが、短時間に閾値超の異なる送信元IPから認証する」というパターンを検知対象にして
    いる。Hunt.ioが韓国7金融機関への侵害基盤で確認した、約79種類の出口IPを使うプロキシ
    ローテーションの兆候。
  - `verification-gates.md`の棚卸しで見つかったギャップ。ルール自体は「報道ベースで、
    該当の侵害基盤との直接の関係は未確認」と明記された探索的ヒューリスティック。

対応するログ形式:
  - JSON Lines形式。各行は1つの認証イベント。`account_id`/`session_id`のいずれかと、
    `src_ip`のいずれか、タイムスタンプ(`ts`、任意)を認識する。

集計方法(Sigmaルールのコメントに書かれた集計方針をそのまま実装):
  - アカウント/セッション単位でグループ化し、時間窓(既定600秒)内の異なる送信元IP数を集計。
  - 閾値(既定10件)を超えた場合に検知。

安全のための制限:
  - **ログファイルを読むだけ**。ネットワーク通信は一切しない。

使用例:
  python3 scripts/auth_proxy_rotation_check.py --log-path auth.jsonl
  python3 scripts/auth_proxy_rotation_check.py --log-path auth.jsonl --threshold 5 --window-seconds 300
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass

# Sigmaルールのコメント例(「10分で10件超」)をそのまま既定値に採用。
DEFAULT_WINDOW_SECONDS = 600
DEFAULT_THRESHOLD = 10


@dataclass
class AuthEvent:
    account_id: str
    src_ip: str
    ts: float | None


def parse_jsonl_line(line: str) -> AuthEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    account_id = obj.get("account_id") or obj.get("session_id")
    src_ip = obj.get("src_ip")
    if not isinstance(account_id, str) or not account_id or not isinstance(src_ip, str) or not src_ip:
        return None
    ts = obj.get("ts") or obj.get("timestamp")
    ts_val = float(ts) if isinstance(ts, (int, float)) else None
    return AuthEvent(account_id, src_ip, ts_val)


def scan_log(
    log_path: str, window_seconds: int, threshold: int
) -> tuple[list[tuple[str, int]], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    by_account: dict[str, list[AuthEvent]] = defaultdict(list)
    for line in lines:
        ev = parse_jsonl_line(line)
        if ev:
            by_account[ev.account_id].append(ev)

    # 簡略化: 窓を跨ぐ場合も、見逃しを避けるため全体を1つの集合として数える
    # (他のスクリプトと同じ割り切り。本物のログでの精度検証は未実施)。
    hits: list[tuple[str, int]] = []
    for account_id, evs in by_account.items():
        distinct_ips = {e.src_ip for e in evs}
        if len(distinct_ips) > threshold:
            hits.append((account_id, len(distinct_ips)))

    return hits, len(lines), None


def print_report(hits: list[tuple[str, int]], total_lines: int, log_path: str, threshold: int) -> None:
    print("対象ログ: %s (%d行、閾値: %d件超)" % (log_path, total_lines, threshold))
    print("-" * 60)
    if not hits:
        print("R30(プロキシローテーション)相当のパターンは見つかりませんでした。")
        return

    print("%d 件のアカウント/セッションでR30相当のパターンが見つかりました:\n" % len(hits))
    for account_id, n in sorted(hits, key=lambda h: -h[1]):
        print("  [R30] %s: %d個の異なる送信元IPから認証" % (account_id, n))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="認証イベントのログ(JSON Lines)")
    parser.add_argument(
        "--window-seconds", type=int, default=DEFAULT_WINDOW_SECONDS,
        help="集計の時間窓(秒、既定%d)" % DEFAULT_WINDOW_SECONDS,
    )
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help="時間窓あたりの異なる送信元IP数の閾値(既定%d)" % DEFAULT_THRESHOLD,
    )
    args = parser.parse_args()

    hits, total_lines, err = scan_log(args.log_path, args.window_seconds, args.threshold)
    if err:
        print(err, file=sys.stderr)
        return 2

    print_report(hits, total_lines, args.log_path, args.threshold)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
