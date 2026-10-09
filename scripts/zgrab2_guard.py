#!/usr/bin/env python3
"""zgrab2_guard: zgrab2 に渡す対象を、許可した範囲だけに限定するガード(確認専用・何にも接続しない)

zgrab2 (https://github.com/zmap/zgrab2) は、対象へ実際に接続してバナー等を取得する能動スキャナで、
許可範囲を制限する機能を持たない。誤って他者の資産や公開インターネットへ向けないよう、
標準入力(またはファイル)の対象を検査し、**許可範囲内のものだけ**を zgrab2 の入力形式で出力する。

  - 許可範囲の判定は netcheck と同じ(netcheck/netcheck.py の expand_targets をそのまま使う)。
    既定は 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16。追加は netcheck/config.json の
    allowed_ranges に書く(自社が管理している範囲だけ)。
  - 1 つでも範囲外・解釈不能な対象が混ざると、**全体を出力せず**終了する(終了コード 2)。
  - 実行のたびに --i-own-these(自社が管理している／書面で許可を得た対象)の明示が必要。
  - 一度に扱うのは config の max_targets(既定 256)まで。
  - このスクリプト自体は、ホスト名の名前解決(DNS)以外、どこにも接続しない。

使い方(許可を得た対象に対してだけ使うこと):
    printf '192.168.1.10\\n192.168.1.0/28\\n' | python3 scripts/zgrab2_guard.py --i-own-these \\
        | zgrab2 http --port 80 > zgrab2.jsonl
    # 結果(zgrab2.jsonl)は vuln_triage.html に読み込める。

出力形式: 1 行 1 ターゲット。IP のみは "IP"、ホスト名は "IP, ホスト名"(zgrab2 の入力形式。ホスト名は
HTTP の Host や TLS の SNI に使われる)。標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NETCHECK = os.path.join(HERE, "..", "netcheck", "netcheck.py")


def load_netcheck():
    """netcheck の判定ロジックを再利用する(許可範囲の定義を 1 か所に保つため)。"""
    spec = importlib.util.spec_from_file_location("netcheck_rules", NETCHECK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser(description="zgrab2 に渡す対象を、許可した範囲だけに限定する")
    ap.add_argument("--file", help="対象の一覧ファイル(省略時は標準入力)。IP / CIDR / ホスト名を改行・カンマ区切り")
    ap.add_argument("--i-own-these", action="store_true", dest="consent",
                    help="入力した対象は、自社が管理している(または書面で許可を得た)ものである")
    a = ap.parse_args()

    if not a.consent:
        print("拒否: --i-own-these が必要です(対象が自社の管理下、または書面の許可があることの明示)。", file=sys.stderr)
        return 2

    nc = load_netcheck()
    cfg = nc.load_config()
    text = open(a.file, encoding="utf-8").read() if a.file else sys.stdin.read()

    try:
        ok, refused = nc.expand_targets(text, cfg)
    except nc.TooMany as e:
        print("拒否: %s" % e, file=sys.stderr)
        return 2
    if refused:
        print("拒否: 許可した範囲の外、または解釈できない対象があります。何も出力しません。", file=sys.stderr)
        for r in refused:
            print("  - " + r, file=sys.stderr)
        print("許可している範囲: " + ", ".join(str(n) for n in nc.allowed_networks(cfg)), file=sys.stderr)
        return 2
    if not ok:
        print("拒否: 対象がありません。", file=sys.stderr)
        return 2

    seen = set()
    for name, ip in ok:
        line = ip if name == ip else "%s, %s" % (ip, name)
        if line not in seen:
            seen.add(line)
            print(line)
    print("許可範囲内の %d 件を出力しました。" % len(seen), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
