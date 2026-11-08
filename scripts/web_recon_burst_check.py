#!/usr/bin/env python3
"""web_recon_burst_check: Webサーバーのアクセスログを読み、R3(偵察的Webアクセス、
管理画面系パスへの列挙バースト)相当のパターンを確認する(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r3_recon_enumeration_burst.yml`は、「管理画面・機微な
    パスへのアクセスで、応答が401/403/404、かつ同一送信元IPから短時間に多数(既定30件超/分)」
    というパターンを検知対象にしている(Strixのようなツールによる総当たり列挙の兆候)。
  - R1/R4/R9/R10(`proxy_egress_check.py`)・R12(`dns_water_torture_check.py`)と同じ理由で、
    このルールをWebサーバーの実アクセスログに対して実行する独立ツールが無かった。

対応するログ形式:
  - Apache/Nginxの標準的なcombined log形式。
    例: `203.0.113.5 - - [08/Nov/2026:00:00:01 +0000] "GET /wp-admin/ HTTP/1.1" 404 196 "-" "curl/7.0"`
  - JSON Lines形式。`src_ip`/`client_ip`のいずれかと、`uri_path`/`path`/`url`のいずれか、
    `status_code`/`status`のいずれかを認識する。

集計方法(Sigmaルールの`timeframe: 1m` / `count() by src_ip > 30`をそのまま実装):
  - 管理画面系パス(`/admin`・`/administrator`・`/wp-login.php`・`/wp-admin/`・`/phpmyadmin/`・
    `/manager/html`・`/console`のいずれかを含む)への、401/403/404応答のリクエストだけを対象にする。
  - タイムスタンプを分単位(既定60秒)の時間窓に丸め、(src_ip, 時間窓)ごとに件数を集計。
  - 閾値(既定30件)を超えた(src_ip, 時間窓)を検知として報告。

安全のための制限:
  - **ログファイルを読むだけ**。ネットワーク通信は一切しない。ログの改変もしない。

使用例:
  python3 scripts/web_recon_burst_check.py --log-path access.log
  python3 scripts/web_recon_burst_check.py --log-path access.jsonl --format jsonl --threshold 10
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass

# r3_recon_enumeration_burst.yml の selection_paths.uri_path|contains と完全に同じ。
R3_SENSITIVE_PATH_SUBSTRINGS = (
    "/admin",
    "/administrator",
    "/wp-login.php",
    "/wp-admin/",
    "/phpmyadmin/",
    "/manager/html",
    "/console",
)

# r3_recon_enumeration_burst.yml の selection_status.status_code と完全に同じ。
R3_STATUS_CODES = {401, 403, 404}


@dataclass
class ParsedRequest:
    src_ip: str
    path: str
    status: int
    window: int  # 分単位のバケット番号(タイムスタンプが無ければ常に0)


# --------------------------------------------------------------------------
# Apache/Nginx combined log形式
# --------------------------------------------------------------------------

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+\S+'
)

_APACHE_TIME_FMT = "%d/%b/%Y:%H:%M:%S"


def _parse_apache_time(ts: str) -> int | None:
    # "[08/Nov/2026:00:00:01 +0000]" -> タイムゾーン部分を落として分までの精度でepoch化。
    main = ts.split(" ")[0]
    try:
        t = time.strptime(main, _APACHE_TIME_FMT)
        return int(time.mktime(t))
    except ValueError:
        return None


def parse_combined_line(line: str, window_seconds: int) -> ParsedRequest | None:
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    try:
        status = int(m.group("status"))
    except ValueError:
        return None
    epoch = _parse_apache_time(m.group("ts"))
    window = (epoch // window_seconds) if epoch is not None else 0
    return ParsedRequest(m.group("ip"), m.group("path"), status, window)


# --------------------------------------------------------------------------
# JSON Lines
# --------------------------------------------------------------------------

_SRC_KEYS = ("src_ip", "client_ip", "client")
_PATH_KEYS = ("uri_path", "path", "url")
_STATUS_KEYS = ("status_code", "status")
_TS_KEYS = ("ts", "timestamp", "time")


def parse_jsonl_line(line: str, window_seconds: int) -> ParsedRequest | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    src_ip = next((obj[k] for k in _SRC_KEYS if isinstance(obj.get(k), str)), None)
    path = next((obj[k] for k in _PATH_KEYS if isinstance(obj.get(k), str)), None)
    status = next((obj[k] for k in _STATUS_KEYS if isinstance(obj.get(k), (int, str))), None)
    if not src_ip or not path or status is None:
        return None
    try:
        status = int(status)
    except (TypeError, ValueError):
        return None

    ts_raw = next((obj[k] for k in _TS_KEYS if k in obj), None)
    window = 0
    if isinstance(ts_raw, (int, float)):
        window = int(ts_raw) // window_seconds

    return ParsedRequest(src_ip, path, status, window)


def _is_sensitive_path(path: str) -> bool:
    return any(s in path for s in R3_SENSITIVE_PATH_SUBSTRINGS)


def scan_log(
    log_path: str,
    fmt: str,
    window_seconds: int,
) -> tuple[dict[tuple[str, int], int], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return {}, 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    if fmt == "auto":
        fmt = "jsonl" if lines and lines[0].strip().startswith("{") else "combined"
    parser = parse_jsonl_line if fmt == "jsonl" else parse_combined_line

    counts: dict[tuple[str, int], int] = defaultdict(int)
    for line in lines:
        parsed = parser(line, window_seconds)
        if not parsed:
            continue
        if parsed.status not in R3_STATUS_CODES:
            continue
        if not _is_sensitive_path(parsed.path):
            continue
        counts[(parsed.src_ip, parsed.window)] += 1

    return dict(counts), len(lines), None


def print_report(
    counts: dict[tuple[str, int], int], total_lines: int, log_path: str, fmt: str, threshold: int
) -> list[tuple[str, int, int]]:
    print("対象ログ: %s (形式: %s、%d行)" % (log_path, fmt, total_lines))
    print("-" * 60)

    hits = [(src_ip, window, n) for (src_ip, window), n in counts.items() if n > threshold]
    if not hits:
        print("R3(偵察的Webアクセス、列挙バースト)相当のパターンは見つかりませんでした。")
        return hits

    print("%d 件の(送信元IP, 時間窓)でR3相当のパターンが見つかりました:\n" % len(hits))
    for src_ip, window, n in sorted(hits, key=lambda h: -h[2]):
        print("  [R3] %s (時間窓#%d): 管理画面系パスへの401/403/404が %d 件" % (src_ip, window, n))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="Webサーバーのアクセスログ")
    parser.add_argument(
        "--format", dest="fmt", choices=["auto", "combined", "jsonl"], default="auto",
        help="ログ形式(既定: autoで先頭行から自動判定)",
    )
    parser.add_argument(
        "--window-seconds", type=int, default=60,
        help="集計の時間窓(秒、既定60=1分、Sigmaルールのtimeframeと同じ)",
    )
    parser.add_argument(
        "--threshold", type=int, default=30,
        help="時間窓あたりの件数の閾値(既定30、Sigmaルールのcondition `> 30`と同じ)",
    )
    args = parser.parse_args()

    counts, total_lines, err = scan_log(args.log_path, args.fmt, args.window_seconds)
    if err:
        print(err, file=sys.stderr)
        return 2

    fmt_used = args.fmt
    if fmt_used == "auto":
        with open(args.log_path, encoding="utf-8", errors="replace") as f:
            first = f.readline()
        fmt_used = "jsonl" if first.strip().startswith("{") else "combined"

    hits = print_report(counts, total_lines, args.log_path, fmt_used, args.threshold)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
