#!/usr/bin/env python3
"""web_recon_burst_check: Webサーバーのアクセスログを読み、R3(偵察的Webアクセス、
管理画面系パスへの列挙バースト)・R18(PHPUnit eval-stdin.php、CVE-2017-9841)・
R19(ThinkPHP invokefunction、CVE-2018-20062)相当のパターンを確認する(確認専用、読み取りのみ)。

R18・R19は2026-11-08追加: どちらも`status: stable`(確定済みの脆弱性パターン)で、
R3と同じWebアクセスログの、URIへの単純な文字列一致(閾値・時間窓は不要、1件でも即検知)。

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

# r18_phpunit_eval_stdin_rce.yml の selection.cs-uri-stem|contains と完全に同じ。
# status: stable(確定済みの脆弱性パターン)。閾値・時間窓は不要、1件でも即検知。
R18_PHPUNIT_PATH_SUBSTRING = "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"

# r19_thinkphp_invokefunction_rce.yml の selection_invokefunction / selection_invoke_func と
# 完全に同じ(両方が同じリクエストに含まれる場合のみ検知)。status: stable。
R19_THINKPHP_SUBSTRINGS = (r"think\app/invokefunction", "call_user_func_array")


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


def _matches_r18(path: str) -> bool:
    return R18_PHPUNIT_PATH_SUBSTRING in path


def _matches_r19(path: str) -> bool:
    return all(s in path for s in R19_THINKPHP_SUBSTRINGS)


@dataclass
class KnownRceHit:
    rule: str  # "R18" or "R19"
    src_ip: str
    path: str
    line_no: int


def scan_log(
    log_path: str,
    fmt: str,
    window_seconds: int,
) -> tuple[dict[tuple[str, int], int], list[KnownRceHit], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return {}, [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    if fmt == "auto":
        fmt = "jsonl" if lines and lines[0].strip().startswith("{") else "combined"
    parser = parse_jsonl_line if fmt == "jsonl" else parse_combined_line

    counts: dict[tuple[str, int], int] = defaultdict(int)
    known_rce_hits: list[KnownRceHit] = []
    for i, line in enumerate(lines, start=1):
        parsed = parser(line, window_seconds)
        if not parsed:
            continue
        if parsed.status in R3_STATUS_CODES and _is_sensitive_path(parsed.path):
            counts[(parsed.src_ip, parsed.window)] += 1
        if _matches_r18(parsed.path):
            known_rce_hits.append(KnownRceHit("R18", parsed.src_ip, parsed.path, i))
        elif _matches_r19(parsed.path):
            known_rce_hits.append(KnownRceHit("R19", parsed.src_ip, parsed.path, i))

    return dict(counts), known_rce_hits, len(lines), None


def print_report(
    counts: dict[tuple[str, int], int],
    known_rce_hits: list[KnownRceHit],
    total_lines: int,
    log_path: str,
    fmt: str,
    threshold: int,
) -> list:
    print("対象ログ: %s (形式: %s、%d行)" % (log_path, fmt, total_lines))
    print("-" * 60)

    r3_hits = [(src_ip, window, n) for (src_ip, window), n in counts.items() if n > threshold]
    all_hits = list(r3_hits) + list(known_rce_hits)
    if not all_hits:
        print("R3(列挙バースト)・R18(PHPUnit eval-stdin.php)・R19(ThinkPHP invokefunction)相当の"
              "パターンは見つかりませんでした。")
        return all_hits

    if r3_hits:
        print("%d 件の(送信元IP, 時間窓)でR3相当のパターンが見つかりました:\n" % len(r3_hits))
        for src_ip, window, n in sorted(r3_hits, key=lambda h: -h[2]):
            print("  [R3] %s (時間窓#%d): 管理画面系パスへの401/403/404が %d 件" % (src_ip, window, n))
    if known_rce_hits:
        print("%d 件のR18/R19相当のリクエストが見つかりました:\n" % len(known_rce_hits))
        for hit in known_rce_hits:
            label = "PHPUnit eval-stdin.php (CVE-2017-9841)" if hit.rule == "R18" else "ThinkPHP invokefunction (CVE-2018-20062)"
            print("  [%s] %s -> %s (行 %d、%s)" % (hit.rule, hit.src_ip, hit.path, hit.line_no, label))
    return all_hits


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

    counts, known_rce_hits, total_lines, err = scan_log(args.log_path, args.fmt, args.window_seconds)
    if err:
        print(err, file=sys.stderr)
        return 2

    fmt_used = args.fmt
    if fmt_used == "auto":
        with open(args.log_path, encoding="utf-8", errors="replace") as f:
            first = f.readline()
        fmt_used = "jsonl" if first.strip().startswith("{") else "combined"

    hits = print_report(counts, known_rce_hits, total_lines, args.log_path, fmt_used, args.threshold)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
