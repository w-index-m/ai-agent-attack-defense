#!/usr/bin/env python3
"""proxy_egress_check: フォワードプロキシのアクセスログを読み、R1(LLM APIへの外向き通信)・
R4(メッセージングAPIへの外向き通信、C2的チャネル)相当の宛先への通信が無いかを確認する
(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r1_llm_api_egress.yml` と `r4_messaging_api_c2.yml` は、
    「どのログを、どう見れば検知になるか」という**ルール定義**であり、Sigma/Datadog/Elastic
    それぞれのクエリ文法に書き起こしたものも、実際に投入する先はSIEM側(Splunk・Datadog・
    Elastic等、既にプロキシログを取り込んでいる基盤)が前提になっている。
  - このリポジトリ自身には、**フォワードプロキシのログを実際に読んで判定するツールが
    無かった**(2026-11-07、会話での指摘により判明)。このスクリプトはそのギャップを埋める、
    ログファイルを直接読む版。SIEMを持たない個人・小規模環境でも、手元のログファイル1本で
    同じ判定ができる。

対応するログ形式:
  - Squidのnative access log形式(最も一般的なフォワードプロキシの標準ログ)。
    例: `1699999999.123    234 10.0.0.5 TCP_TUNNEL/200 512 CONNECT api.openai.com:443 - HIER_DIRECT/1.2.3.4 -`
  - JSON Lines形式(1行1 JSONオブジェクト。クラウドプロキシ・自作ログでよく使われる形)。
    `dest_host`/`host`/`url` のいずれかと、`src_ip`/`client_ip`/`client` のいずれかを認識する。

ドメイン一覧は、r1/r4のSigmaルールと完全に同じもの(唯一の定義はshared/taxonomy.jsonだが、
このドメイン一覧自体はSigmaルール側にしか無いため、そちらをコピーした。ズレないよう、
値を変える場合は両方を直すこと)。

安全のための制限:
  - **ログファイルを読むだけ**。ネットワーク通信は一切しない。ログの改変もしない。
  - 「サーバ系ゾーン」の判定は環境依存のため、既定では全ての送信元IPを対象にする
    (--server-cidr で絞り込み、--exclude-cidr で除外も可能)。

使用例:
  python3 scripts/proxy_egress_check.py --log-path /var/log/squid/access.log
  python3 scripts/proxy_egress_check.py --log-path proxy.jsonl --format jsonl --server-cidr 10.0.0.0/8
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse

# r1_llm_api_egress.yml の selection_domain.dest_host と完全に同じ(コピー元が唯一の
# 一次情報。変更時は両方直すこと)。
R1_LLM_API_DOMAINS = {
    "api.openai.com",
    "api.anthropic.com",
    "api.openrouter.ai",
    "openrouter.ai",
    "api.deepseek.com",
    "api.groq.com",  # Groq is an inference host, not a model -- serves Llama/Gemma/Mixtral etc.
    "generativelanguage.googleapis.com",  # Google Gemini/Gemma public API
}

# r4_messaging_api_c2.yml の selection_domain.dest_host と完全に同じ。
R4_MESSAGING_API_DOMAINS = {
    "api.telegram.org",
    "discord.com",
    "discordapp.com",
    "slack.com",
    "hooks.slack.com",
    "textsecure-service.whispersystems.org",
}


def _host_matches(dest_host: str, domains: set[str]) -> bool:
    """完全一致、または対象ドメインのサブドメイン(例: foo.openrouter.ai)を拾う。"""
    dest_host = dest_host.lower().rstrip(".")
    if dest_host in domains:
        return True
    return any(dest_host.endswith("." + d) for d in domains)


@dataclass
class ProxyHit:
    src_ip: str
    dest_host: str
    rule: str  # "R1" or "R4"
    line_no: int
    raw_line: str = field(repr=False)


# --------------------------------------------------------------------------
# Squid native access log
# --------------------------------------------------------------------------

_SQUID_RE = re.compile(
    r"^\s*(?P<ts>\d+\.\d+)\s+(?P<elapsed>\d+)\s+(?P<client>\S+)\s+(?P<action>\S+)\s+"
    r"(?P<size>\d+)\s+(?P<method>\S+)\s+(?P<url>\S+)"
)


def _host_from_squid_url(method: str, url: str) -> str | None:
    if method.upper() == "CONNECT":
        # CONNECT の URL は "host:port" の形。
        host = url.rsplit(":", 1)[0] if ":" in url else url
        return host or None
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed.hostname


def parse_squid_line(line: str, line_no: int) -> tuple[str, str] | None:
    """(src_ip, dest_host) を返す。パースできない行はNone。"""
    m = _SQUID_RE.match(line)
    if not m:
        return None
    host = _host_from_squid_url(m.group("method"), m.group("url"))
    if not host:
        return None
    return m.group("client"), host


# --------------------------------------------------------------------------
# JSON Lines
# --------------------------------------------------------------------------

_SRC_KEYS = ("src_ip", "client_ip", "client", "source_ip")
_HOST_KEYS = ("dest_host", "host", "destination_host")
_URL_KEYS = ("url", "uri", "request_url")


def parse_jsonl_line(line: str, line_no: int) -> tuple[str, str] | None:
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
    host = next((obj[k] for k in _HOST_KEYS if isinstance(obj.get(k), str)), None)
    if not host:
        url = next((obj[k] for k in _URL_KEYS if isinstance(obj.get(k), str)), None)
        if url:
            host = urlparse(url if "://" in url else "http://" + url).hostname
    if not src_ip or not host:
        return None
    return src_ip, host


# --------------------------------------------------------------------------
# ゾーン絞り込み(送信元IPが対象範囲かどうか)
# --------------------------------------------------------------------------


def _in_any_network(ip_str: str, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def is_in_scope(
    src_ip: str,
    server_nets: list,
    exclude_nets: list,
) -> bool:
    if exclude_nets and _in_any_network(src_ip, exclude_nets):
        return False
    if server_nets:
        return _in_any_network(src_ip, server_nets)
    return True  # 絞り込み指定が無ければ、全ての送信元を対象にする(ルールの既定どおり)


# --------------------------------------------------------------------------
# スキャン本体
# --------------------------------------------------------------------------


def scan_log(
    log_path: str,
    fmt: str,
    server_nets: list,
    exclude_nets: list,
) -> tuple[list[ProxyHit], int, str | None]:
    """(hits, 読んだ行数, エラー文字列) を返す。"""
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return [], 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    if fmt == "auto":
        fmt = "jsonl" if lines and lines[0].strip().startswith("{") else "squid"

    parser = parse_jsonl_line if fmt == "jsonl" else parse_squid_line

    hits: list[ProxyHit] = []
    for i, line in enumerate(lines, start=1):
        parsed = parser(line, i)
        if not parsed:
            continue
        src_ip, dest_host = parsed
        if not is_in_scope(src_ip, server_nets, exclude_nets):
            continue
        if _host_matches(dest_host, R1_LLM_API_DOMAINS):
            hits.append(ProxyHit(src_ip, dest_host, "R1", i, line.rstrip("\n")))
        elif _host_matches(dest_host, R4_MESSAGING_API_DOMAINS):
            hits.append(ProxyHit(src_ip, dest_host, "R4", i, line.rstrip("\n")))

    return hits, len(lines), None


def print_report(hits: list[ProxyHit], total_lines: int, log_path: str, fmt: str) -> None:
    print("対象ログ: %s (形式: %s、%d行)" % (log_path, fmt, total_lines))
    print("-" * 60)
    if not hits:
        print("R1(LLM API)・R4(メッセージングAPI)相当の宛先への通信は見つかりませんでした。")
        return

    by_pair: dict[tuple[str, str, str], list[ProxyHit]] = {}
    for h in hits:
        by_pair.setdefault((h.rule, h.src_ip, h.dest_host), []).append(h)

    print("%d 件の通信ペアで、計 %d 行が一致しました:\n" % (len(by_pair), len(hits)))
    for (rule, src_ip, dest_host), group in sorted(by_pair.items()):
        label = "LLM API への外向き通信" if rule == "R1" else "メッセージング API への外向き通信(C2的チャネル)"
        print("  [%s] %s (%s) -> %s: %d 回 (例: 行 %d)" % (
            rule, src_ip, label, dest_host, len(group), group[0].line_no,
        ))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="フォワードプロキシのアクセスログファイル")
    parser.add_argument(
        "--format", dest="fmt", choices=["auto", "squid", "jsonl"], default="auto",
        help="ログ形式(既定: autoで先頭行から自動判定)",
    )
    parser.add_argument(
        "--server-cidr", action="append", default=[], metavar="CIDR",
        help="このCIDRに属する送信元IPだけを対象にする(repeatable)。指定が無ければ全件対象",
    )
    parser.add_argument(
        "--exclude-cidr", action="append", default=[], metavar="CIDR",
        help="このCIDRに属する送信元IPを対象から除外する(repeatable。開発者端末等)",
    )
    args = parser.parse_args()

    try:
        server_nets = [ipaddress.ip_network(c) for c in args.server_cidr]
        exclude_nets = [ipaddress.ip_network(c) for c in args.exclude_cidr]
    except ValueError as exc:
        print("CIDRの指定が不正です: %s" % exc, file=sys.stderr)
        return 2

    hits, total_lines, err = scan_log(args.log_path, args.fmt, server_nets, exclude_nets)
    if err:
        print(err, file=sys.stderr)
        return 2

    fmt_used = args.fmt
    if fmt_used == "auto":
        with open(args.log_path, encoding="utf-8", errors="replace") as f:
            first = f.readline()
        fmt_used = "jsonl" if first.strip().startswith("{") else "squid"

    print_report(hits, total_lines, args.log_path, fmt_used)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
