#!/usr/bin/env python3
"""jndi_rce_check: ネットワーク接続ログを読み、R29(JNDI/LDAPインジェクション型RCE、
Log4Shell系)相当のパターンを確認する(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r29_jndi_ldap_rce_attempt.yml`は、「Java/Tomcatのプロセスが、
    LDAP(389/636)・RMI(1099)ポートへの新規アウトバウンド接続を行う」というJNDIインジェクション
    (Log4Shell、CVE-2021-44228等)の典型パターンを検知対象にしている。
  - `verification-gates.md`の棚卸しで見つかったギャップ。ルール自体は「報道ベース(Hunt.io)で、
    韓国7金融機関への侵害基盤での関係は未確認」と明記された探索的ヒューリスティック。

対応するログ形式:
  - JSON Lines形式。各行は1つのアウトバウンド接続イベント。`image`/`process_name`のいずれかと、
    `dest_port`/`DestinationPort`のいずれか、`dest_host`/`DestinationHostname`(任意、
    許可リスト判定用)を認識する。

安全のための制限:
  - **ログファイルを読むだけ**。ネットワーク通信は一切しない。

使用例:
  python3 scripts/jndi_rce_check.py --log-path connections.jsonl
  python3 scripts/jndi_rce_check.py --log-path connections.jsonl --allowlist-suffix ldap.internal.example
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

# r29_jndi_ldap_rce_attempt.yml の selection_parent.Image|endswith と完全に同じ。
R29_JAVA_PROCESS_SUFFIXES = ("/java", "/tomcat", "/catalina.sh")

# r29_jndi_ldap_rce_attempt.yml の selection_dest_port.DestinationPort と完全に同じ。
R29_SUSPICIOUS_PORTS = {389, 636, 1099}


@dataclass
class ConnEvent:
    image: str
    dest_host: str
    dest_port: int | None
    line_no: int


def parse_jsonl_line(line: str, line_no: int) -> ConnEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    image = obj.get("image") or obj.get("Image") or obj.get("process_name")
    if not isinstance(image, str) or not image:
        return None
    dest_host = obj.get("dest_host") or obj.get("DestinationHostname") or obj.get("DestinationIp") or ""
    port_raw = obj.get("dest_port") or obj.get("DestinationPort")
    try:
        dest_port = int(port_raw) if port_raw is not None else None
    except (TypeError, ValueError):
        dest_port = None
    return ConnEvent(image, str(dest_host), dest_port, line_no)


def _matches_r29(ev: ConnEvent, allowlist_suffixes: list[str]) -> bool:
    if not ev.image.endswith(R29_JAVA_PROCESS_SUFFIXES):
        return False
    if ev.dest_port not in R29_SUSPICIOUS_PORTS:
        return False
    host = ev.dest_host.lower().rstrip(".")
    if any(host.endswith(s.lower()) for s in allowlist_suffixes):
        return False
    return True


def scan_log(log_path: str, allowlist_suffixes: list[str]) -> tuple[list[ConnEvent], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    hits: list[ConnEvent] = []
    for i, line in enumerate(lines, start=1):
        ev = parse_jsonl_line(line, i)
        if not ev:
            continue
        if _matches_r29(ev, allowlist_suffixes):
            hits.append(ev)

    return hits, len(lines), None


def print_report(hits: list[ConnEvent], total_lines: int, log_path: str) -> None:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)
    if not hits:
        print("R29(JNDI/LDAPインジェクション型RCE)相当のパターンは見つかりませんでした。")
        return

    print("%d 件の接続でR29相当のパターンが見つかりました:\n" % len(hits))
    for ev in hits:
        print(
            "  [R29] %s -> %s:%s (行 %d)"
            % (ev.image, ev.dest_host or "(不明)", ev.dest_port, ev.line_no)
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="ネットワーク接続イベントのログ(JSON Lines)")
    parser.add_argument(
        "--allowlist-suffix", action="append", default=[], metavar="SUFFIX",
        help="この宛先ホスト名サフィックス(例: ldap.internal.example)は正規のLDAP/ADサーバーとして"
        "除外する(repeatable)",
    )
    args = parser.parse_args()

    hits, total_lines, err = scan_log(args.log_path, args.allowlist_suffix)
    if err:
        print(err, file=sys.stderr)
        return 2

    print_report(hits, total_lines, args.log_path)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
