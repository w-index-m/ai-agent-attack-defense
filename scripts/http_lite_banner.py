#!/usr/bin/env python3
"""http_lite_banner: zgrab2 が使えない環境向けの、HTTP/HTTPS バナー取得だけの軽量な代替。

[zmap/zgrab2](https://github.com/zmap/zgrab2) は HTTP 以外にも SSH・TLS 詳細・SMB・制御系(OT/ICS)
など 20 以上のプロトコルに対応する本格的なアクティブスキャナ(Go 製、別途ビルドが必要)。本スクリプトは
そのうち「対象へ GET を送り、ステータスコードと応答ヘッダを記録する」部分だけを、Python の標準
ライブラリ(http.client / ssl)だけで再現したもので、zgrab2 の代替ではなく**軽量な補完**。
TLS ハンドシェイクの詳細(証明書検証・プロトコルバージョンの記録など)は行わない(平文 HTTP /
証明書検証なしの HTTPS への GET と、応答ヘッダの記録のみ)。

出力形式は意図的に zgrab2 の http モジュールの出力と互換にしてある
(vuln_triage.html の zgrab2 取り込みロジックをそのまま再利用するため):
  1 行 1 対象の JSON、
  {"ip": "...", "data": {"http": {"status": "success", "protocol": "http", "port": 80,
   "result": {"response": {"status_code": 200, "headers": {...}}}}}}

能動的に対象へ接続するため、zgrab2 や scripts/zgrab2_guard.py と同じ同意(--i-own-these)・
許可範囲判定(netcheck/netcheck.py の expand_targets をそのまま再利用)が必要。

使い方(許可を得た対象に対してだけ使うこと):
    printf '192.168.1.10\\n' | python3 scripts/http_lite_banner.py --i-own-these > httplite.jsonl
    # → httplite.jsonl を vuln_triage.html に貼る/選ぶ(zgrab2 として自動判別される)
"""
import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import socket
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NETCHECK = os.path.join(HERE, "..", "netcheck", "netcheck.py")
USER_AGENT = "Mozilla/5.0 (compatible; vuln-triage-http-lite-banner/1.0)"
DEFAULT_PORTS = [(80, False), (443, True)]  # (port, TLSを使うか)


def load_netcheck():
    """netcheck の判定ロジックを再利用する(許可範囲の定義を 1 か所に保つため)。"""
    spec = importlib.util.spec_from_file_location("netcheck_rules_httplite", NETCHECK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def grab(ip, port, use_tls, host=None, timeout=5.0):
    """1つの ip:port へ GET / を送り、zgrab2 の http モジュールと互換の結果を返す(例外は出さない)。"""
    host_header = host or ip
    result = {"protocol": "http", "port": port}
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # バナー取得が目的で、証明書の検証はしない
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", "/", headers={"Host": host_header, "User-Agent": USER_AGENT, "Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(8192)
        conn.close()
        headers = {}
        for k, v in resp.getheaders():
            key = k.lower().replace("-", "_")
            headers.setdefault(key, []).append(v)
        result["status"] = "success"
        result["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result["result"] = {"response": {
            "status_code": resp.status,
            "status_line": "%d %s" % (resp.status, resp.reason),
            "headers": headers,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "content_length": len(body),
        }}
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "connection-timeout"
        result["error"] = "タイムアウトしました(%s秒)" % timeout
        return result
    except ConnectionRefusedError:
        result["status"] = "connection-refused"
        result["error"] = "接続を拒否されました"
        return result
    except ssl.SSLError as e:
        # 平文(HTTP)のポートへ --tls で接続した場合など、TLSハンドシェイクそのものの失敗。
        # タイムアウトではないので、connection-timeoutとは区別する。
        result["status"] = "protocol-error"
        result["error"] = "TLSハンドシェイクに失敗しました: %s" % e
        return result
    except OSError as e:
        result["status"] = "unknown-error"
        result["error"] = str(e)
        return result
    except Exception as e:  # noqa: BLE001 - 対象側の予期しない応答でもサーバー全体を落とさない
        result["status"] = "unknown-error"
        result["error"] = str(e)
        return result


def grab_target(ip, host=None, ports=None, timeout=5.0):
    """1つの対象に対し、既定でポート80(http)・443(https)の両方を試し、zgrab2互換の行(複数)を返す。"""
    rows = []
    for port, use_tls in (ports or DEFAULT_PORTS):
        entry = grab(ip, port, use_tls, host=host, timeout=timeout)
        row = {"ip": ip, "data": {"http": entry}}
        if host and host != ip:
            row["domain"] = host
        rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser(description="zgrab2が使えない環境向けの、HTTP/HTTPSバナー取得だけの軽量な代替")
    ap.add_argument("--file", help="対象の一覧ファイル(省略時は標準入力)。IP / CIDR / ホスト名を改行・カンマ区切り")
    ap.add_argument("--i-own-these", action="store_true", dest="consent",
                     help="入力した対象は、自社が管理している(または書面で許可を得た)ものである")
    ap.add_argument("--timeout", type=float, default=5.0, help="接続タイムアウト秒(既定5秒)")
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
        print("拒否: 許可した範囲の外、または解釈できない対象があります。何も実行しません。", file=sys.stderr)
        for r in refused:
            print("  - " + r, file=sys.stderr)
        print("許可している範囲: " + ", ".join(str(n) for n in nc.allowed_networks(cfg)), file=sys.stderr)
        return 2
    if not ok:
        print("拒否: 対象がありません。", file=sys.stderr)
        return 2

    for name, ip in ok:
        host = name if name != ip else None
        for row in grab_target(ip, host=host, timeout=a.timeout):
            print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
