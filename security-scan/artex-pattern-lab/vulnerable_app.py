"""R29/R30/R31 の検知ロジックを確認するための、唯一の最小アプリ(意図的に脆弱)。

Hunt.io の報道(2026-11-04、ARTEX / 韓国 7 金融機関への侵害基盤)にあった 3 つの挙動を、
**3 つ別々のアプリを作らず、1 つのアプリにまとめて**再現する:

  - /jndi, /jndi_safe        : JNDI ルックアップ文字列を受け取り、LDAP/RMI へ接続する(R29)
  - /login                   : X-Forwarded-For を信用し、同一アカウントへの認証試行を記録する(R30)
  - /crypto_relay, /crypto_relay_safe : 指定されたホストへ中継する、サーバー側のジョブ(R31)

このラボ自体に対する脆弱性診断ではない(sqli-lab と同じ位置づけ)。接続先は、すべて
127.0.0.0/8 のローカルな、自分で用意した模擬サーバーに限定する(本物の LDAP サーバーや
暗号資産取引所には、一切接続しない)。

ローカル/プライベート範囲以外には撃てない、という安全策は、auto_vuln_scanner.py と
同じ考え方(_is_allowed_target 相当)を、ここでは「接続先ホストの許可リスト」という
形で入れている。
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from pathlib import Path

from flask import Flask, g, jsonify, request

app = Flask(__name__)

EVENTS_PATH = Path(__file__).with_name("events.jsonl")

# このラボが実際に接続してよい先(自分で用意したローカルの模擬サーバーのみ)。
# 本物の LDAP サーバー・本物の暗号資産取引所には、絶対に接続しない。
_ALLOWED_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8",)]

JNDI_RE = re.compile(r"^\$\{jndi:(?:ldap|rmi)://([^:/]+):(\d+)(?:/.*)?\}$")

# R31 の本物のルール(r31_*.yml)が見ているのは、実際の取引所ドメインの一覧。
# このラボでは、本物の取引所には接続せず、同じ「サーバーからの取引所 API 相当への
# 直接アクセス」という形だけを、ローカルな模擬ホスト名(*.exchange.lab)で再現する。
EXCHANGE_LIKE_SUFFIXES = (".exchange.lab",)


def _log_event(event: dict) -> None:
    event.setdefault("ts", time.time())
    with open(EVENTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def _host_allowed(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError):
        return False
    return any(ip in net for net in _ALLOWED_NETS)


# --- R29: JNDI インジェクション → LDAP/RMI への接続 --------------------------

def _try_jndi_connect(raw: str, safe: bool) -> dict:
    m = JNDI_RE.match(raw.strip())
    if not m:
        return {"matched": False}
    host, port = m.group(1), int(m.group(2))
    if safe:
        # 修正版: ${jndi:...} という形そのものを拒否する(ホワイトリストではなく、
        # 危険なスキームを拒否する形。Log4Shell の一般的な緩和策と同じ考え方)。
        return {"matched": True, "connected": False, "reason": "rejected (jndi scheme is not allowed)"}
    if not _host_allowed(host):
        return {"matched": True, "connected": False, "reason": "host not in lab-allowed range"}
    try:
        with socket.create_connection((host, port), timeout=2):
            pass
        connected = True
        reason = "connected"
    except OSError as e:
        connected = False
        reason = "connect failed: %s" % e
    # R29 のルールが見ているのは「Java プロセスが、受信直後に LDAP/RMI へ新規接続」。
    # このラボは Python 製だが、本物のデプロイでは Java プロセスが行う挙動なので、
    # process_name は実際の検知対象に合わせて記録する(ラボの制約として明記)。
    _log_event({
        "event": "network_connection", "process_name": "java", "parent_process_name": "java",
        "destination_ip": host, "destination_port": port, "endpoint": "/jndi" if not safe else "/jndi_safe",
    })
    return {"matched": True, "connected": connected, "reason": reason}


@app.route("/jndi", methods=["GET"])
def jndi():
    result = _try_jndi_connect(request.args.get("q", ""), safe=False)
    return jsonify(result)


@app.route("/jndi_safe", methods=["GET"])
def jndi_safe():
    result = _try_jndi_connect(request.args.get("q", ""), safe=True)
    return jsonify(result)


# --- R30: 同一アカウントへの、多数の送信元 IP からの認証 ---------------------

@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    # X-Forwarded-For は、本来プロキシだけが設定すべきヘッダーだが、このラボは
    # 「送信元 IP を偽装できる」という前提を単純化するため、そのまま信用する
    # (本番のアプリが、信頼できないプロキシの XFF を無条件に信じると起きる問題でもある)。
    src_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ok = username == "alice" and password == "alice_pw_123"
    _log_event({
        "event": "authentication", "account_id": username, "src_ip": src_ip, "result": "ok" if ok else "failed",
    })
    return jsonify({"ok": ok})


# --- R31: サーバーから、暗号資産取引所 API 相当への直接アクセス ----------------

@app.route("/crypto_relay", methods=["GET"])
def crypto_relay():
    return _crypto_relay(safe=False)


@app.route("/crypto_relay_safe", methods=["GET"])
def crypto_relay_safe():
    return _crypto_relay(safe=True)


def _crypto_relay(safe: bool):
    host = request.args.get("host", "")
    if safe:
        # 修正版: サーバー自身が、取引所 API 相当のホストへ直接出ることを、そもそも許可しない
        # (その種の連携が必要なら、専用の、監査対象のサービス経由にする、という設計上の対策)。
        if host.endswith(EXCHANGE_LIKE_SUFFIXES):
            return jsonify({"relayed": False, "reason": "server-to-exchange-API egress is not allowed"})
    if not _host_allowed(host):
        return jsonify({"relayed": False, "reason": "host not in lab-allowed range"})
    try:
        with socket.create_connection((host, 80), timeout=2):
            pass
        relayed = True
    except OSError as e:
        relayed = False
        return jsonify({"relayed": False, "reason": "connect failed: %s" % e})
    if host.endswith(EXCHANGE_LIKE_SUFFIXES):
        _log_event({
            "event": "proxy", "src_zone": "server", "destination_hostname": host, "endpoint": "/crypto_relay",
        })
    return jsonify({"relayed": relayed})


if __name__ == "__main__":
    app.run(port=5000)
