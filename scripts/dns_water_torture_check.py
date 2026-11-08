#!/usr/bin/env python3
"""dns_water_torture_check: 再帰DNSリゾルバのクエリログを読み、R12(DNS水攻め/ランダム
サブドメイン攻撃)相当のパターンを確認する(確認専用、読み取りのみ)。

背景:
  - `security-scan/detections/sigma/r12_dns_water_torture.yml`は、「単一の登録ドメイン配下で、
    多数の異なる(疑似ランダムな)サブドメインへの問い合わせが、短時間に急増する」というパターンを
    検知対象にしている。再帰リゾルバが毎回キャッシュミスして権威DNSサーバーへ転送し続け、
    権威サーバー側のリソースを枯渇させる攻撃。
  - R1/R4(`proxy_egress_check.py`)と同じ理由で、このルールを実際のDNSクエリログに対して
    実行する独立ツールが無かったため作成した。

対応するログ形式:
  - JSON Lines形式のみ(1行1 JSONオブジエクト)。各行に、クエリ対象ドメイン(`dns_query`/`query`/
    `qname`のいずれか)と、応答(`dns_answer`/`answer`/`rcode`のいずれか。'NXDOMAIN'かどうかを見る)
    を認識する。タイムスタンプがあれば`ts`/`timestamp`/`time`のいずれかを読む(無くても動くが、
    その場合は全体を1つの集計対象として扱う)。

集計方法(Sigmaルールのコメントに書かれた集計方針をそのまま実装):
  - クエリを「登録ドメイン」(eTLD+1、簡易実装: 最後の2ラベル。例: foo.bar.example.com →
    example.com)単位でグループ化。
  - 既定1分の時間窓ごとに、登録ドメインごとの「異なるサブドメイン数」と「NXDOMAIN率」を計算。
  - 異なるサブドメイン数が閾値(既定200)を超え、かつNXDOMAIN率が閾値(既定80%)を超える場合に
    検知。

安全のための制限:
  - **ログファイルを読むだけ**。ネットワーク通信は一切しない。ログの改変もしない。

使用例:
  python3 scripts/dns_water_torture_check.py --log-path dns.jsonl
  python3 scripts/dns_water_torture_check.py --log-path dns.jsonl --subdomain-threshold 50 --nxdomain-ratio 0.5
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass

_QUERY_KEYS = ("dns_query", "query", "qname")
_ANSWER_KEYS = ("dns_answer", "answer", "rcode")
_TS_KEYS = ("ts", "timestamp", "time")


def _registered_domain(qname: str) -> str:
    """簡易eTLD+1抽出: 最後の2ラベルを登録ドメインとみなす(複合TLD(.co.jpなど)は非対応、
    と明記のうえの割り切り)。"""
    qname = qname.strip().rstrip(".").lower()
    labels = qname.split(".")
    if len(labels) < 2:
        return qname
    return ".".join(labels[-2:])


@dataclass
class ParsedQuery:
    qname: str
    is_nxdomain: bool
    window: int  # 時間窓のバケット番号(タイムスタンプが無ければ常に0)


def parse_jsonl_line(line: str, window_seconds: int) -> ParsedQuery | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    qname = next((obj[k] for k in _QUERY_KEYS if isinstance(obj.get(k), str)), None)
    if not qname:
        return None
    answer = next((obj[k] for k in _ANSWER_KEYS if isinstance(obj.get(k), str)), "")
    is_nxdomain = answer.strip().upper() == "NXDOMAIN"

    ts_raw = next((obj[k] for k in _TS_KEYS if k in obj), None)
    window = 0
    if isinstance(ts_raw, (int, float)):
        window = int(ts_raw) // window_seconds

    return ParsedQuery(qname, is_nxdomain, window)


@dataclass
class DomainWindowStats:
    registered_domain: str
    window: int
    subdomains: set
    nxdomain_count: int = 0
    total_count: int = 0


def scan_log(
    log_path: str,
    window_seconds: int,
    allowlist_suffixes: list[str],
) -> tuple[dict[tuple[str, int], DomainWindowStats], int, str | None]:
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        return {}, 0, "%s の読み取りに失敗しました: %s" % (log_path, exc)

    stats: dict[tuple[str, int], DomainWindowStats] = {}
    for line in lines:
        parsed = parse_jsonl_line(line, window_seconds)
        if not parsed:
            continue
        reg_domain = _registered_domain(parsed.qname)
        if any(reg_domain.endswith(s.lower().lstrip(".")) for s in allowlist_suffixes):
            continue
        key = (reg_domain, parsed.window)
        if key not in stats:
            stats[key] = DomainWindowStats(reg_domain, parsed.window, set())
        st = stats[key]
        st.subdomains.add(parsed.qname.strip().rstrip(".").lower())
        st.total_count += 1
        if parsed.is_nxdomain:
            st.nxdomain_count += 1

    return stats, len(lines), None


def print_report(
    stats: dict[tuple[str, int], DomainWindowStats],
    total_lines: int,
    log_path: str,
    subdomain_threshold: int,
    nxdomain_ratio_threshold: float,
) -> list[DomainWindowStats]:
    print("対象ログ: %s (%d行)" % (log_path, total_lines))
    print("-" * 60)

    hits = []
    for st in stats.values():
        distinct = len(st.subdomains)
        ratio = (st.nxdomain_count / st.total_count) if st.total_count else 0.0
        if distinct >= subdomain_threshold and ratio >= nxdomain_ratio_threshold:
            hits.append(st)

    if not hits:
        print("R12(DNS水攻め)相当のパターンは見つかりませんでした。")
        return hits

    print("%d 件の(登録ドメイン, 時間窓)でR12相当のパターンが見つかりました:\n" % len(hits))
    for st in sorted(hits, key=lambda s: (-len(s.subdomains), s.registered_domain)):
        ratio = st.nxdomain_count / st.total_count
        print(
            "  [R12] %s (時間窓#%d): 異なるサブドメイン %d件、NXDOMAIN率 %.0f%%(%d/%d件)"
            % (st.registered_domain, st.window, len(st.subdomains), ratio * 100, st.nxdomain_count, st.total_count)
        )
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log-path", required=True, help="DNSクエリログ(JSON Lines)")
    parser.add_argument(
        "--window-seconds", type=int, default=60,
        help="集計の時間窓(秒、既定60=1分)。タイムスタンプが無いログでは無視される",
    )
    parser.add_argument(
        "--subdomain-threshold", type=int, default=200,
        help="時間窓あたりの異なるサブドメイン数の閾値(既定200、Sigmaルールのコメントと同じ)",
    )
    parser.add_argument(
        "--nxdomain-ratio", type=float, default=0.8,
        help="NXDOMAIN率の閾値(既定0.8=80%%、Sigmaルールのコメントと同じ)",
    )
    parser.add_argument(
        "--allowlist-suffix", action="append", default=[], metavar="SUFFIX",
        help="この登録ドメインサフィックス(例: internal.example)は対象から除外する(repeatable)",
    )
    args = parser.parse_args()

    stats, total_lines, err = scan_log(args.log_path, args.window_seconds, args.allowlist_suffix)
    if err:
        print(err, file=sys.stderr)
        return 2

    hits = print_report(stats, total_lines, args.log_path, args.subdomain_threshold, args.nxdomain_ratio)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
