#!/usr/bin/env python3
"""bind_version_check: ISC BIND 9の、2026-10-21公開のセキュリティリリース(4件のCVE、
BIND 9.20.30 / 9.21.27で修正)の対象になりうるかを確認する(確認専用)。

背景:
  - 2026-10-21、ISCがBIND 9.20.30・9.21.27・9.20.30-S1をリリースし、4件のCVEを修正。
    (本リポジトリの R22 参照)
  - CVE-2026-94300(CVSS 8.1、最高): GSS-TSIGで署名されたUDPメッセージのリプレイで
    namedのメモリが破損。自分が管理するゾーンへの細工クエリと組み合わせると、潜在的に
    リモートコード実行に繋がりうるとISCが報告(確定ではなく「可能性」の表現)。
    報告者: OpenAIのDave Aitel。回避策なし。
  - CVE-2026-96888: redirectゾーン+qname-minimization strictの組み合わせでassertion
    failure(異常終了、DoS)。
  - CVE-2026-19630: 名前圧縮を多用した細工パケットでCPU/メモリを過剰消費(resource
    exhaustion)。
  - CVE-2026-97313: RPZゾーンを2つ以上使い、recursive-only設定が食い違う構成で、
    RD=1→RD=0のクエリ順序によりassertion failure(DoS)。
  - 影響範囲: 9.11.0〜9.18.50(9.18系はEOLのため修正版なし)、9.20.0〜9.20.29、
    9.21.0〜9.21.26系列(Supported Preview Edition含む)。

このツールが確認すること:
  - ローカルモード(既定): このホストの `named -v` の出力からバージョンを読み取り、
    上記の影響範囲と照合する。
  - ネットワークモード(--query HOST、要--i-own-these): 指定したリゾルバへCHAOSクラス
    のTXTレコード(version.bind)を1回だけ問い合わせ、応答のバージョン文字列を照合する。
    これはBIND運用で広く使われる標準的な確認手法そのもの(悪用ではない)。対象は
    netcheck と同じ許可範囲判定(既定: 社内のプライベートIP)に限定する。

安全のための制限:
  - **確認だけ**。named の設定変更、ゾーンデータの書き換え、ネットワークへの送信は
    「CHAOS TXT問い合わせ」1回のみ(--queryを指定した場合だけ)。
  - --query を使う場合は、netcheck/config.json の allowed_ranges で許可した範囲だけが
    対象(zgrab2_guard.py と同じ判定ロジックを再利用)。
  - named のバージョン表記はビルドによって揺れがあるため、厳密なセマンティック
    バージョン比較ではなく、既知の脆弱なブランチ/パッチレベルとの近似照合に留める。
    不明な場合は「断定しない」。

使い方:
    python3 scripts/bind_version_check.py
    python3 scripts/bind_version_check.py --out bind_check.sarif
    python3 scripts/bind_version_check.py --query 127.0.0.1 --i-own-these

標準ライブラリだけで動く(Python 3.8 以上)。
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import socket
import struct
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "bind-version-check"

HERE = os.path.dirname(os.path.abspath(__file__))
NETCHECK = os.path.join(HERE, "..", "netcheck", "netcheck.py")

CVES = [
    ("CVE-2026-94300", "GSS-TSIGリプレイによるメモリ破損(潜在的RCE)", "CVSS 8.1、回避策なし"),
    ("CVE-2026-96888", "redirectゾーン+qname-minimization strictでassertion failure", "DoS、回避策なし"),
    ("CVE-2026-19630", "名前圧縮の多用によるリソース枯渇", "DoS"),
    ("CVE-2026-97313", "RPZゾーンのrecursive-only不一致でassertion failure", "DoS"),
]

REFERENCE = (
    "ISC BIND 9セキュリティリリース(2026-10-21、9.20.30/9.21.27で修正): "
    "https://kb.isc.org/docs/cve-2026-94300 "
    "(直接アクセスで確認できない場合は Canadian Centre for Cyber Security AV26-1072 等の"
    "複数の独立したソースで裏取りすること)。"
)

# `named -v` 出力は "BIND 9.20.15-S1 ..." のように "BIND " が付くが、CHAOS TXT
# (version.bind)の応答は素のバージョン文字列("9.20.15-S1" 等)のことが多いため、
# "BIND " は任意(あれば読み飛ばす)として両対応にする。
VERSION_RE = re.compile(r"(?:BIND\s+)?(\d+)\.(\d+)\.(\d+)")


def load_netcheck():
    spec = importlib.util.spec_from_file_location("netcheck_rules", NETCHECK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def assess_version(major: int, minor: int, patch: int) -> tuple[str, str]:
    """既知の脆弱範囲との近似照合。named のバージョン表記はディストリでバックポート
    されることがあるため、厳密な断定ではなく「このブランチ・パッチレベルは影響範囲に
    該当するように見える」という参考情報として返す。"""
    if major != 9:
        return "info", "BIND 9系ではありません(major=%d)。今回のCVEの対象外です。" % major

    if 11 <= minor <= 18:
        return (
            "high",
            "9.%d.%d は影響範囲(9.11.0〜9.18.50)に該当するように見えます。"
            "9.18系はEOLのため、ISCからの修正版はありません。ベンダーのバックポート版を"
            "使っている場合は、ディストリ側のアドバイザリで修正状況を確認してください。"
            % (minor, patch),
        )
    if minor == 20:
        if patch < 30:
            return "high", "9.20.%d は影響範囲(9.20.0〜9.20.29)に該当するように見えます。9.20.30以降へ更新してください。" % patch
        return "info", "9.20.%d は修正済みバージョン(9.20.30以降)に見えます。" % patch
    if minor == 21:
        if patch < 27:
            return "high", "9.21.%d は影響範囲(9.21.0〜9.21.26)に該当するように見えます。9.21.27以降へ更新してください。" % patch
        return "info", "9.21.%d は修正済みバージョン(9.21.27以降)に見えます。" % patch

    return (
        "medium",
        "9.%d.%d は今回の4件のCVEの影響範囲表(9.11-9.18 / 9.20.0-29 / 9.21.0-26)に"
        "直接は該当しませんが、新しいブランチの可能性もあるため、ISC公式アドバイザリで"
        "直接確認してください。" % (minor, patch),
    )


def check_local() -> tuple[str, str, str | None]:
    """ローカルの `named -v` を実行してバージョン文字列を取得する(読み取りのみ)。"""
    try:
        out = subprocess.run(
            ["named", "-v"], capture_output=True, text=True, timeout=10
        )
    except FileNotFoundError:
        return "info", "このホストに `named` コマンドが見つかりません(BIND未インストール、またはPATH外)。", None
    except Exception as e:
        return "medium", "named -v の実行に失敗しました: %s" % e, None

    text = (out.stdout or "") + (out.stderr or "")
    m = VERSION_RE.search(text)
    if not m:
        return "medium", "named -v の出力からバージョンを読み取れませんでした: %r" % text.strip()[:200], None
    major, minor, patch = (int(x) for x in m.groups())
    severity, message = assess_version(major, minor, patch)
    return severity, message, text.strip().splitlines()[0] if text.strip() else None


def build_chaos_txt_query() -> bytes:
    """CHAOSクラスの TXT レコード(version.bind)問い合わせパケットを組み立てる。
    BIND運用で広く使われる標準的な確認手法(dig -c CHAOS -t TXT version.bind と等価)。"""
    tid = int.from_bytes(os.urandom(2), "big")
    flags = 0x0000  # 標準問い合わせ、再帰不要
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b"\x07version\x04bind\x00"
    question = qname + struct.pack(">HH", 16, 3)  # QTYPE=TXT(16), QCLASS=CH(3)
    return tid, header + question


def parse_chaos_txt_reply(data: bytes, expect_tid: int) -> str | None:
    """応答からTXTレコードの文字列を1つ取り出す(最小限のパーサ。圧縮ポインタは
    質問セクションを指す1パターンのみ対応すれば十分)。"""
    if len(data) < 12:
        return None
    tid, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if tid != expect_tid or ancount < 1:
        return None
    pos = 12
    # 質問セクションをスキップ
    for _ in range(qdcount):
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0:
                pos += 2
                break
            pos += data[pos] + 1
        else:
            pos += 1
        pos += 4  # QTYPE + QCLASS
    # 回答セクション
    for _ in range(ancount):
        if pos >= len(data):
            return None
        if data[pos] & 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        if pos + 10 > len(data):
            return None
        rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlength]
        pos += rdlength
        if rtype == 16 and rdata:  # TXT
            txt_len = rdata[0]
            return rdata[1:1 + txt_len].decode("ascii", errors="replace")
    return None


def check_query(target: str, timeout: float = 3.0) -> tuple[str, str, str | None]:
    tid, pkt = build_chaos_txt_query()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (target, 53))
            data, _ = s.recvfrom(4096)
    except socket.timeout:
        return "info", "%s:53 から応答がありませんでした(CHAOS問い合わせが無効化されている可能性、またはBINDではない)。" % target, None
    except OSError as e:
        return "medium", "%s への問い合わせに失敗しました: %s" % (target, e), None

    txt = parse_chaos_txt_reply(data, tid)
    if not txt:
        return "info", "%s から version.bind の応答を解釈できませんでした(CHAOSが無効、または形式が異なる)。" % target, None

    m = VERSION_RE.search(txt)
    if not m:
        return "info", "%s のバージョン文字列からバージョン番号を読み取れませんでした: %r" % (target, txt), txt
    major, minor, patch = (int(x) for x in m.groups())
    severity, message = assess_version(major, minor, patch)
    return severity, "%s: %s" % (target, message), txt


def to_sarif(severity: str, message: str, version_text: str | None) -> dict:
    level = {"high": "error", "medium": "warning", "info": "note"}.get(severity, "warning")
    results = [{
        "ruleId": "bind-version-check",
        "level": level,
        "message": {"text": "%s %s" % (message, REFERENCE)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "bind:version"}}}],
        "properties": {"severityLabel": severity, "versionText": version_text or ""},
    }]
    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {"name": DRIVER,
                                "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": datetime.now(timezone.utc).isoformat(timespec="seconds")}],
            "results": results,
        }],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="", help="SARIFの出力先(省略時は標準出力に要約のみ表示)")
    ap.add_argument("--query", default="", help="このホストのnamedではなく、指定したリゾルバにCHAOS TXT問い合わせで確認する(要 --i-own-these)")
    ap.add_argument("--i-own-these", action="store_true", dest="consent",
                    help="--query の対象は、自社が管理している(または書面で許可を得た)ものである")
    args = ap.parse_args()

    if args.query:
        if not args.consent:
            print("拒否: --query を使うには --i-own-these が必要です。", file=sys.stderr)
            return 2
        nc = load_netcheck()
        cfg = nc.load_config()
        try:
            ok, refused = nc.expand_targets(args.query, cfg)
        except nc.TooMany as e:
            print("拒否: %s" % e, file=sys.stderr)
            return 2
        if refused or not ok:
            print("拒否: 許可した範囲の外、または解釈できない対象です。", file=sys.stderr)
            print("許可している範囲: " + ", ".join(str(n) for n in nc.allowed_networks(cfg)), file=sys.stderr)
            return 2
        _, ip = ok[0]
        severity, message, version_text = check_query(ip)
    else:
        severity, message, version_text = check_local()

    print("[%s] %s" % (severity, message))
    if version_text:
        print("バージョン文字列: %s" % version_text)
    print()
    print("対象のCVE一覧(2026-10-21公開のBINDセキュリティリリース):")
    for cve, subsystem, note in CVES:
        print("  %s (%s): %s" % (cve, subsystem, note))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(severity, message, version_text), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
