#!/usr/bin/env python3
"""multi_proto_lite: zgrab2 が使えない環境向けの、複数プロトコルのバナー取得/接続確認の軽量な代替。

scripts/http_lite_banner.py が HTTP/HTTPS だけを対象にしたのに対し、こちらはそれ以外のよく使われる
プロトコル(SSH・FTP・Telnet・SMTP・Redis・Memcached・MySQL・PostgreSQL・TLS 詳細・MongoDB・
MSSQL・Oracle)を対象にする。zgrab2 本体(Go 製)の代替ではなく、標準ライブラリだけで実装できる範囲の
軽量な補完。

対応の深さはプロトコルごとに違う(誠実さを優先し、できる範囲だけを実装している):
  - バナーを相手から自分で送ってくるプロトコル(SSH/FTP/Telnet/SMTP/MySQL)は、接続して最初の応答
    を読むだけ(バナー取得)。
  - こちらから最小限のコマンドだけ送って応答を確認するもの(Redis: PING、Memcached: version、
    PostgreSQL: SSLRequest への応答で平文/TLS対応のどちらかを確認)。認証やデータの読み書きは行わない。
  - TLS: Python の ssl モジュールで実際にハンドシェイクし、プロトコルバージョンを記録する。証明書の
    有効期限は、`cryptography` パッケージがあれば読み取る(無ければバージョン情報のみ。
    `pip install cryptography`)。
  - MongoDB/MSSQL/Oracle は、プロトコル固有のハンドシェイクを実装していない(バイナリプロトコルが
    複雑で、この環境に実機の検証手段が無いため)。TCP 接続の可否だけを確認する「接続確認のみ」と
    して、結果にも明示する。

出力形式は zgrab2 の各モジュールの出力と互換にしてある(vuln_triage.html の zgrab2 取り込みロジック
をそのまま再利用するため)。能動的に対象へ接続するため、zgrab2 / http_lite_banner.py と同じ同意
(--i-own-these)・許可範囲判定(netcheck と共通)が必要。

使い方(許可を得た対象に対してだけ使うこと):
    printf '192.168.1.10\\n' | python3 scripts/multi_proto_lite.py --module ssh --i-own-these
    # → 標準出力(JSON Lines)を vuln_triage.html に貼る/選ぶ(zgrab2 として自動判別される)
"""
import argparse
import importlib.util
import json
import os
import socket
import ssl
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NETCHECK = os.path.join(HERE, "..", "netcheck", "netcheck.py")

DEFAULT_PORTS = {
    "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25, "redis": 6379,
    "memcached": 11211, "mysql": 3306, "postgres": 5432, "tls": 443,
    "mongodb": 27017, "mssql": 1433, "oracle": 1521,
}
# プロトコル固有のハンドシェイクを実装していない(TCP接続の可否だけを確認する)モジュール。
CONNECT_ONLY_MODULES = frozenset(["mongodb", "mssql", "oracle"])


def load_netcheck():
    """netcheck の判定ロジックを再利用する(許可範囲の定義を 1 か所に保つため)。"""
    spec = importlib.util.spec_from_file_location("netcheck_rules_multiproto", NETCHECK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect(ip, port, timeout):
    return socket.create_connection((ip, port), timeout=timeout)


def _recv_some(sock, timeout, max_bytes=512):
    """タイムアウトまでに受信したバイト列を、改行までか最大長まで返す(何も届かなくても例外にしない)。"""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < max_bytes:
            chunk = sock.recv(max_bytes - len(buf))
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
    except socket.timeout:
        pass
    return buf


def _conn_error(exc, timeout):
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return {"status": "connection-timeout", "error": "タイムアウトしました(%s秒)" % timeout}
    if isinstance(exc, ConnectionRefusedError):
        return {"status": "connection-refused", "error": "接続を拒否されました"}
    if isinstance(exc, ssl.SSLError):
        return {"status": "protocol-error", "error": "TLSハンドシェイクに失敗しました: %s" % exc}
    return {"status": "unknown-error", "error": str(exc)}


def grab_ssh(ip, port, timeout):
    try:
        with _connect(ip, port, timeout) as s:
            raw = _recv_some(s, timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    banner = raw.decode("utf-8", "replace").strip("\r\n")
    software = ""
    if banner.startswith("SSH-"):
        parts = banner.split("-", 2)
        if len(parts) == 3:
            software = parts[2].split(" ")[0]
    return {"status": "success", "result": {"server_id": {"raw": banner, "software": software}}}


def _grab_text_banner(ip, port, timeout):
    try:
        with _connect(ip, port, timeout) as s:
            raw = _recv_some(s, timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    banner = raw.decode("utf-8", "replace").strip("\r\n")
    return {"status": "success", "result": {"banner": banner}}


def grab_ftp(ip, port, timeout):
    return _grab_text_banner(ip, port, timeout)


def grab_smtp(ip, port, timeout):
    return _grab_text_banner(ip, port, timeout)


def grab_telnet(ip, port, timeout):
    return _grab_text_banner(ip, port, timeout)


def _grab_send_then_read(ip, port, timeout, payload):
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(payload)
            raw = _recv_some(s, timeout)
    except OSError as e:
        return None, _conn_error(e, timeout)
    return raw, None


def grab_redis(ip, port, timeout):
    raw, err = _grab_send_then_read(ip, port, timeout, b"PING\r\n")
    if err:
        return err
    resp = raw.decode("utf-8", "replace").strip("\r\n")
    return {"status": "success", "result": {"ping_response": resp}}


def grab_memcached(ip, port, timeout):
    raw, err = _grab_send_then_read(ip, port, timeout, b"version\r\n")
    if err:
        return err
    resp = raw.decode("utf-8", "replace").strip("\r\n")
    return {"status": "success", "result": {"banner": resp}}


def _mysql_parse_version(payload):
    """MySQLの初期ハンドシェイクパケットのペイロードから、サーバーのバージョン文字列を取り出す。
    形式: [1byte protocol_version][null終端のversion文字列](以降は使わない)。失敗しても例外にしない。"""
    try:
        if len(payload) < 2:
            return ""
        nul = payload.index(b"\x00", 1)
        return payload[1:nul].decode("ascii", "replace")
    except Exception:
        return ""


def grab_mysql(ip, port, timeout):
    try:
        with _connect(ip, port, timeout) as s:
            s.settimeout(timeout)
            header = s.recv(4)
            if len(header) < 4:
                return {"status": "success", "result": {"banner": ""}}
            length = header[0] | (header[1] << 8) | (header[2] << 16)
            payload = b""
            while len(payload) < length:
                chunk = s.recv(length - len(payload))
                if not chunk:
                    break
                payload += chunk
    except OSError as e:
        return _conn_error(e, timeout)
    return {"status": "success", "result": {"banner": _mysql_parse_version(payload)}}


def grab_postgres(ip, port, timeout):
    """PostgreSQLへ最小限のSSLRequest(8バイト)だけを送り、'S'(TLS対応)/'N'(非対応)の1バイト応答を
    見る(libpqが実際に使う、認証情報を一切送らない読み取り専用の手順)。認証もクエリも行わない。"""
    payload = (8).to_bytes(4, "big") + (80877103).to_bytes(4, "big")
    raw, err = _grab_send_then_read(ip, port, timeout, payload)
    if err:
        return err
    if raw == b"S":
        note, tls = "TLS対応(SSLRequestに'S'で応答)", True
    elif raw == b"N":
        note, tls = "TLS非対応(SSLRequestに'N'で応答)", False
    else:
        note, tls = "応答なし、またはPostgreSQLではない可能性", None
    return {"status": "success", "result": {"banner": "PostgreSQL: " + note, "tls_supported": tls}}


def grab_connect_only(ip, port, timeout):
    """プロトコル固有のハンドシェイクは実装していない対象向けの、TCP接続可否だけの確認。"""
    try:
        with _connect(ip, port, timeout):
            pass
    except OSError as e:
        return _conn_error(e, timeout)
    return {"status": "success", "result": {"note": "TCP接続のみ確認(プロトコルハンドシェイクは未実装)"}}


def _tls_cert_validity_end(der_bytes):
    """証明書(DER)の有効期限(終了)をISO8601で返す。`cryptography`が無ければNone(その機能だけ諦める)。"""
    if not der_bytes:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        end = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        return end.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def grab_tls(ip, port, timeout, host=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # バナー取得が目的で、証明書の検証はしない
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host or ip) as s:
                version = s.version()
                der = s.getpeercert(binary_form=True)
    except OSError as e:
        return _conn_error(e, timeout)
    handshake_log = {"server_hello": {"version": {"name": version}}}
    cert_end = _tls_cert_validity_end(der)
    if cert_end:
        handshake_log["server_certificates"] = {"certificate": {"parsed": {"validity": {"end": cert_end}}}}
    return {"status": "success", "result": {"handshake_log": handshake_log}}


GRABBERS = {
    "ssh": lambda ip, port, timeout, host: grab_ssh(ip, port, timeout),
    "ftp": lambda ip, port, timeout, host: grab_ftp(ip, port, timeout),
    "telnet": lambda ip, port, timeout, host: grab_telnet(ip, port, timeout),
    "smtp": lambda ip, port, timeout, host: grab_smtp(ip, port, timeout),
    "redis": lambda ip, port, timeout, host: grab_redis(ip, port, timeout),
    "memcached": lambda ip, port, timeout, host: grab_memcached(ip, port, timeout),
    "mysql": lambda ip, port, timeout, host: grab_mysql(ip, port, timeout),
    "postgres": lambda ip, port, timeout, host: grab_postgres(ip, port, timeout),
    "tls": lambda ip, port, timeout, host: grab_tls(ip, port, timeout, host=host),
    "mongodb": lambda ip, port, timeout, host: grab_connect_only(ip, port, timeout),
    "mssql": lambda ip, port, timeout, host: grab_connect_only(ip, port, timeout),
    "oracle": lambda ip, port, timeout, host: grab_connect_only(ip, port, timeout),
}


def grab(module, ip, port, timeout=5.0, host=None):
    """1つの対象に対し、指定モジュールのプローブを行い、zgrab2互換のエントリ(dataの中身)を返す。"""
    fn = GRABBERS.get(module)
    if fn is None:
        return {"status": "unknown-error", "error": "未対応のモジュール: %s" % module,
                "protocol": module, "port": port}
    entry = fn(ip, port, timeout, host)
    entry.setdefault("protocol", module)
    entry.setdefault("port", port)
    entry.setdefault("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    return entry


def grab_target(module, ip, port=None, host=None, timeout=5.0):
    port = port or DEFAULT_PORTS.get(module)
    if port is None:
        raise ValueError("ポートが指定されておらず、既定値もありません: %s" % module)
    entry = grab(module, ip, port, timeout=timeout, host=host)
    row = {"ip": ip, "data": {module: entry}}
    if host and host != ip:
        row["domain"] = host
    return row


def main():
    ap = argparse.ArgumentParser(description="zgrab2が使えない環境向けの、複数プロトコルのバナー取得/接続確認の軽量な代替")
    ap.add_argument("--module", required=True, choices=sorted(DEFAULT_PORTS.keys()),
                     help="対象プロトコル(" + "/".join(sorted(DEFAULT_PORTS.keys())) + ")")
    ap.add_argument("--port", type=int, help="対象ポート(省略時はモジュールごとの既定値)")
    ap.add_argument("--file", help="対象の一覧ファイル(省略時は標準入力)。IP / CIDR / ホスト名を改行・カンマ区切り")
    ap.add_argument("--i-own-these", action="store_true", dest="consent",
                     help="入力した対象は、自社が管理している(または書面で許可を得た)ものである")
    ap.add_argument("--timeout", type=float, default=5.0, help="接続タイムアウト秒(既定5秒)")
    a = ap.parse_args()

    if not a.consent:
        print("拒否: --i-own-these が必要です(対象が自社の管理下、または書面の許可があることの明示)。", file=sys.stderr)
        return 2
    if a.module in CONNECT_ONLY_MODULES:
        print("注意: %s はプロトコル固有のハンドシェイクを実装していません。TCP接続の可否だけを確認します。"
              % a.module, file=sys.stderr)

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
        row = grab_target(a.module, ip, port=a.port, host=host, timeout=a.timeout)
        print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
