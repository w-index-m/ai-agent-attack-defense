#!/usr/bin/env python3
"""multi_proto_lite: zgrab2 が使えない環境向けの、複数プロトコルのバナー取得/接続確認の軽量な代替。

scripts/http_lite_banner.py が HTTP/HTTPS だけを対象にしたのに対し、こちらはそれ以外のよく使われる
プロトコル(SSH・FTP・Telnet・SMTP・Redis・Memcached・MySQL・PostgreSQL・TLS 詳細・MongoDB・
MSSQL・Oracle・SMB・RDP・SNMP・MQTT・AMQP・IPP・SOCKS5・PPTP・Modbus)を対象にする。zgrab2 本体
(Go 製)の代替ではなく、標準ライブラリだけで実装できる範囲の軽量な補完。

対応の深さはプロトコルごとに違う(誠実さを優先し、できる範囲だけを実装している):
  - バナーを相手から自分で送ってくるプロトコル(SSH/FTP/Telnet/SMTP/MySQL)は、接続して最初の応答
    を読むだけ(バナー取得)。
  - こちらから最小限のコマンド/パケットだけ送って応答を確認するもの(Redis: PING、
    Memcached: version、PostgreSQL: SSLRequest、SOCKS5: バージョン・認証方式ネゴシエーション、
    MQTT: CONNECT、SNMP: GetRequest(sysDescr.0, UDP)、SMB: SMB2 Negotiate、RDP: X.224/RDP
    Negotiation、Modbus: Read Holding Registers(読み取り専用のfunction code 0x03、1レジスタのみ))。
    認証やデータの書き込みは行わない。
  - TLS: Python の ssl モジュールで実際にハンドシェイクし、プロトコルバージョンを記録する。証明書の
    有効期限は、`cryptography` パッケージがあれば読み取る(無ければバージョン情報のみ。
    `pip install cryptography`)。
  - AMQP/MongoDB: プロトコル仕様どおりの最初の1往復(AMQPはプロトコルヘッダ、MongoDBはOP_MSGの
    hello)は送るが、応答本体の完全なデコードはせず、印字可能な文字列を抜き出す簡易抽出に留める
    (フィールドテーブル/BSONの完全なパーサーは実装していない)。
  - MSSQL(TDS PRELOGIN)/Oracle(TNS CONNECT)/PPTP(Start-Control-Connection-Request)は、各
    プロトコル仕様に基づいて実装したが、このサンドボックスには実機(本物のSQL Server/Oracle/
    PPTPサーバー)が無く、自作の模擬応答での自己テストしか行えていない。実機での結果と異なる
    可能性がある。
  - 制御系(OT/ICS)は、Modbusの読み取り専用コマンドだけに限定した。DNP3/BACnet/Siemens S7等の
    独自プロトコルは、実機が無く検証できないこと、不正なパケットで機器が予期せぬ挙動を起こす
    リスクが相対的に高いことから、実装を見送っている。

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
import random
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
    "smb": 445, "rdp": 3389, "snmp": 161, "mqtt": 1883, "amqp": 5672,
    "ipp": 631, "socks5": 1080, "pptp": 1723, "modbus": 502,
}
# このサンドボックスには実機(本物のサーバー/機器)が無く、自作の模擬応答での自己テストしか
# 行えていないモジュール。実機での結果と異なる可能性がある(詳細はモジュール docstring 参照)。
UNVERIFIED_AGAINST_REAL_SERVER = frozenset(["mssql", "oracle", "pptp"])


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


def _recv_exact(sock, n, timeout):
    """ちょうどn バイト受信する(相手が先に切断したら、そこまでの分だけ返す。例外は出さない)。"""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf


def _udp_send_recv(ip, port, payload, timeout, max_bytes=2048):
    """UDPで1パケット送り、1パケット受信する(SNMP用)。例外は出さず、(raw, error)のタプルを返す。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            raw, _ = s.recvfrom(max_bytes)
        finally:
            s.close()
    except (socket.timeout, TimeoutError):
        return None, {"status": "connection-timeout", "error": "タイムアウトしました(%s秒、応答がありません)" % timeout}
    except ConnectionRefusedError:
        return None, {"status": "connection-refused", "error": "接続を拒否されました(ICMP port unreachable)"}
    except OSError as e:
        return None, {"status": "unknown-error", "error": str(e)}
    return raw, None


def _extract_printable(data, min_len=4, max_items=8):
    """バイト列から印字可能なASCIIの連続部分だけを抜き出す簡易抽出(プロトコルの完全なデコードはしない)。"""
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return " / ".join(out[:max_items])


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


def grab_socks5(ip, port, timeout):
    """SOCKS5のバージョン・認証方式ネゴシエーションだけを行う(RFC 1928)。実際の中継(CONNECT等)は
    行わない。"""
    raw, err = _grab_send_then_read(ip, port, timeout, b"\x05\x01\x00")  # ver5, 1method, no-auth
    if err:
        return err
    if len(raw) >= 2 and raw[0] == 5:
        methods = {0x00: "認証不要", 0x02: "ユーザー名/パスワード認証", 0xFF: "受け入れ可能な方式無し"}
        note = methods.get(raw[1], "0x%02x" % raw[1])
        return {"status": "success", "result": {"banner": "SOCKS5応答(選択認証方式: %s)" % note}}
    return {"status": "success", "result": {"banner": "SOCKS5応答として解釈できませんでした",
                                             "raw_hex": raw[:20].hex()}}


def _mqtt_varint(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n == 0:
            break
    return bytes(out)


def grab_mqtt(ip, port, timeout):
    """MQTT 3.1.1のCONNECTパケットを送り、CONNACKの戻りコードを見る(RFC非公式仕様、OASIS標準)。
    サブスクライブやパブリッシュは行わない。"""
    client_id = b"vtlite-probe"
    var_header = b"\x00\x04MQTT\x04\x02\x00\x3c"  # proto name, level4, flags(clean session), keepalive60
    payload = len(client_id).to_bytes(2, "big") + client_id
    body = var_header + payload
    packet = bytes([0x10]) + _mqtt_varint(len(body)) + body
    raw, err = _grab_send_then_read(ip, port, timeout, packet)
    if err:
        return err
    if len(raw) >= 4 and raw[0] == 0x20:
        codes = {0: "accepted", 1: "不正なプロトコルバージョン", 2: "クライアントID拒否",
                 3: "サーバー利用不可", 4: "ユーザー名/パスワード不正", 5: "未認可"}
        rc = raw[3]
        return {"status": "success", "result": {"banner": "MQTT CONNACK: " + codes.get(rc, "code=%d" % rc)}}
    return {"status": "success", "result": {"banner": "MQTT応答として解釈できませんでした",
                                             "raw_hex": raw[:20].hex()}}


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ber_tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _ber_int(n):
    if n == 0:
        payload = b"\x00"
    else:
        payload = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if payload[0] & 0x80:
            payload = b"\x00" + payload
    return _ber_tlv(0x02, payload)


def _ber_oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        chunk = []
        while p > 0:
            chunk.insert(0, p & 0x7F)
            p >>= 7
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        out.extend(chunk)
    return _ber_tlv(0x06, bytes(out))


def _ber_read_tlv(buf, pos):
    tag = buf[pos]
    pos += 1
    ln = buf[pos]
    pos += 1
    if ln & 0x80:
        nbytes = ln & 0x7F
        ln = int.from_bytes(buf[pos:pos + nbytes], "big")
        pos += nbytes
    value = buf[pos:pos + ln]
    pos += ln
    return tag, value, pos


def _snmp_parse_response(raw):
    """SNMP GetResponse-PDUから、sysDescr.0(文字列)だけを取り出す簡易デコード。失敗したらNone。"""
    try:
        tag, msg, _ = _ber_read_tlv(raw, 0)
        if tag != 0x30:
            return None
        p = 0
        _, _version, p = _ber_read_tlv(msg, p)
        _, _community, p = _ber_read_tlv(msg, p)
        pdu_tag, pdu, p = _ber_read_tlv(msg, p)
        if pdu_tag != 0xA2:  # GetResponse-PDU
            return None
        pp = 0
        _, _reqid, pp = _ber_read_tlv(pdu, pp)
        _, err_status, pp = _ber_read_tlv(pdu, pp)
        pp_ = pp
        _, _err_idx, pp = _ber_read_tlv(pdu, pp)
        if err_status and err_status != b"\x00":
            return "エラー応答(error-status=%d)" % int.from_bytes(err_status, "big")
        vbl_tag, vbl, pp = _ber_read_tlv(pdu, pp)
        if vbl_tag != 0x30:
            return None
        vb_tag, vb, _ = _ber_read_tlv(vbl, 0)
        if vb_tag != 0x30:
            return None
        bp = 0
        _, _oid, bp = _ber_read_tlv(vb, bp)
        val_tag, val, bp = _ber_read_tlv(vb, bp)
        if val_tag == 0x04:  # OCTET STRING
            return "sysDescr: " + val.decode("utf-8", "replace")
        return "値のタグ=0x%02x(文字列以外、未対応)" % val_tag
    except Exception:
        return None


def grab_snmp(ip, port, timeout):
    """SNMP v2cのGetRequestで、sysDescr.0(1.3.6.1.2.1.1.1.0)を読み取り専用で取得する(RFC 1157/3416)。
    コミュニティ名は'public'固定。UDPのため接続拒否はICMP port unreachableの有無で判定される。"""
    req_id = random.randint(1, 0x7FFFFFFF)
    varbind = _ber_tlv(0x30, _ber_oid("1.3.6.1.2.1.1.1.0") + _ber_tlv(0x05, b""))
    varbind_list = _ber_tlv(0x30, varbind)
    pdu_body = _ber_int(req_id) + _ber_int(0) + _ber_int(0) + varbind_list
    pdu = _ber_tlv(0xA0, pdu_body)  # GetRequest-PDU
    packet = _ber_tlv(0x30, _ber_int(1) + _ber_tlv(0x04, b"public") + pdu)  # version=2c(1)
    raw, err = _udp_send_recv(ip, port, packet, timeout)
    if err:
        return err
    parsed = _snmp_parse_response(raw)
    if parsed is None:
        return {"status": "success", "result": {"banner": "SNMP応答を解析できませんでした",
                                                  "raw_hex": raw[:60].hex()}}
    return {"status": "success", "result": {"banner": parsed}}


SMB_DIALECTS = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
                0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1"}


def _smb2_negotiate_packet():
    header = (
        b"\xfeSMB" + (64).to_bytes(2, "little") + b"\x00\x00" + b"\x00\x00\x00\x00" +
        (0).to_bytes(2, "little") + b"\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" +
        b"\x00" * 8 + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00" * 8 + b"\x00" * 16
    )
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (
        (36).to_bytes(2, "little") + len(dialects).to_bytes(2, "little") +
        (1).to_bytes(2, "little") + b"\x00\x00" + b"\x00\x00\x00\x00" + b"\x00" * 16 + b"\x00" * 8
    )
    for d in dialects:
        body += d.to_bytes(2, "little")
    smb2_packet = header + body
    return b"\x00" + len(smb2_packet).to_bytes(3, "big") + smb2_packet


def grab_smb(ip, port, timeout):
    """SMB2 Negotiate Requestを送り、サーバーが選んだdialect(プロトコルバージョン)を見る
    (MS-SMB2)。認証やファイル操作は行わない。"""
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(_smb2_negotiate_packet())
            nbss_header = _recv_exact(s, 4, timeout)
            if len(nbss_header) < 4:
                return {"status": "success", "result": {"banner": "応答がありません(SMBではない可能性)"}}
            length = int.from_bytes(nbss_header[1:4], "big")
            body_raw = _recv_exact(s, length, timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    if len(body_raw) < 64 or body_raw[:4] != b"\xfeSMB":
        return {"status": "success", "result": {"banner": "SMB2応答として解釈できませんでした",
                                                  "raw_hex": body_raw[:16].hex()}}
    body = body_raw[64:]
    if len(body) < 4:
        return {"status": "success", "result": {"banner": "SMB2 Negotiate Responseが短すぎます"}}
    dialect = int.from_bytes(body[4:6], "little")
    name = SMB_DIALECTS.get(dialect, "0x%04x" % dialect)
    return {"status": "success", "result": {"banner": "SMB2応答(dialect: %s)" % name}}


def _rdp_negotiate_packet():
    neg_req = (
        bytes([0x01, 0x00]) + (8).to_bytes(2, "little") + (0x00000003).to_bytes(4, "little")
    )  # type=NEG_REQ, flags=0, length=8, requestedProtocols=SSL|HYBRID
    x224_body = bytes([0xE0]) + b"\x00\x00" + b"\x00\x00" + bytes([0x00]) + neg_req
    x224 = bytes([len(x224_body)]) + x224_body
    tpkt_len = 4 + len(x224)
    return b"\x03\x00" + tpkt_len.to_bytes(2, "big") + x224


def grab_rdp(ip, port, timeout):
    """X.224 Connection Request + RDP Negotiation Requestを送り、サーバーが選んだセキュリティ
    プロトコル(TLS/CredSSP等)を見る(MS-RDPBCGR)。ログオンや画面の操作は行わない。"""
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(_rdp_negotiate_packet())
            tpkt_header = _recv_exact(s, 4, timeout)
            if len(tpkt_header) < 4 or tpkt_header[0] != 3:
                return {"status": "success",
                        "result": {"banner": "TPKT応答として解釈できませんでした(RDPではない可能性)"}}
            total_len = int.from_bytes(tpkt_header[2:4], "big")
            body = _recv_exact(s, max(0, total_len - 4), timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    if len(body) < 6 or body[1] != 0xD0:
        return {"status": "success", "result": {"banner": "X.224 Connection Confirmではない応答",
                                                  "raw_hex": body[:20].hex()}}
    if len(body) >= 15 and body[7] == 0x02:
        selected = int.from_bytes(body[11:15], "little")
        names = {0: "RDP標準セキュリティ(非推奨)", 1: "TLS", 2: "CredSSP/NLA", 8: "RDSTLS"}
        return {"status": "success",
                "result": {"banner": "RDP応答(選択プロトコル: %s)" % names.get(selected, "0x%x" % selected)}}
    return {"status": "success", "result": {"banner": "RDP応答(Negotiation Response無し)"}}


def grab_amqp(ip, port, timeout):
    """AMQP 0-9-1(RabbitMQ等)のプロトコルヘッダだけを送り、サーバーのConnection.Start応答から
    印字可能な文字列を簡易抽出する(フィールドテーブルの完全なデコードはしない)。認証は行わない。"""
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(b"AMQP\x00\x00\x09\x01")
            s.settimeout(timeout)
            raw = s.recv(4096)
    except OSError as e:
        return _conn_error(e, timeout)
    if not raw:
        return {"status": "success", "result": {"banner": "応答がありません"}}
    if raw[:4] == b"AMQP":
        return {"status": "success", "result": {"banner": "サーバーもプロトコルヘッダのみ応答"
                                                  "(バージョン不一致の可能性): " + raw.hex()}}
    printable = _extract_printable(raw, max_items=24)
    return {"status": "success", "result": {
        "banner": "AMQP Connection.Start応答(簡易抽出): " + (printable or "(印字可能な文字列なし)")}}


def _ipp_attr(tag, name, value_bytes):
    return bytes([tag]) + len(name).to_bytes(2, "big") + name + len(value_bytes).to_bytes(2, "big") + value_bytes


def grab_ipp(ip, port, timeout, host=None):
    """IPP(HTTP上で動く印刷プロトコル)のCUPS-Get-Printers要求を送り、HTTP/IPPの応答コードだけを
    見る(RFC 8010/CUPS拡張)。印刷ジョブの投入は行わない。"""
    body = (
        b"\x01\x01" + (0x4002).to_bytes(2, "big") + b"\x00\x00\x00\x01" + bytes([0x01]) +
        _ipp_attr(0x47, b"attributes-charset", b"utf-8") +
        _ipp_attr(0x48, b"attributes-natural-language", b"en") +
        bytes([0x03])
    )
    req = ("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: application/ipp\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n") % (host or ip, len(body))
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(req.encode("ascii") + body)
            s.settimeout(timeout)
            raw = b""
            while len(raw) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
    except OSError as e:
        return _conn_error(e, timeout)
    idx = raw.find(b"\r\n\r\n")
    if idx == -1:
        return {"status": "success", "result": {"banner": "HTTP応答を解釈できませんでした"}}
    status_line = raw[:idx].decode("latin1", "replace").splitlines()[0] if raw[:idx] else ""
    ipp_body = raw[idx + 4:]
    if len(ipp_body) >= 4:
        status_code = int.from_bytes(ipp_body[2:4], "big")
        note = "IPP応答(HTTP: %s, IPP status-code: 0x%04x)" % (status_line, status_code)
    else:
        note = "IPP応答(HTTP: %s, IPPボディ無し)" % status_line
    return {"status": "success", "result": {"banner": note}}


MODBUS_EXCEPTIONS = {1: "不正なファンクションコード", 2: "不正なデータアドレス", 3: "不正なデータ値",
                      4: "スレーブデバイス故障", 6: "スレーブデバイスビジー"}


def grab_modbus(ip, port, timeout):
    """Modbus TCPの「Read Holding Registers」(ファンクションコード0x03、読み取り専用)を、
    先頭1レジスタだけ要求する(Modbus Application Protocol仕様)。書き込み系コマンドは一切送らない。
    OT/ICS機器は不正なパケットで予期せぬ挙動を起こすことが知られているため、最小限の標準的な
    読み取りコマンドに限定している。"""
    pdu = bytes([0x03]) + (0).to_bytes(2, "big") + (1).to_bytes(2, "big")  # addr=0, qty=1
    length = len(pdu) + 1
    unit_id = 1
    mbap = (1).to_bytes(2, "big") + b"\x00\x00" + length.to_bytes(2, "big") + bytes([unit_id])
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(mbap + pdu)
            header = _recv_exact(s, 7, timeout)
            if len(header) < 7:
                return {"status": "success",
                        "result": {"banner": "応答が短すぎます(Modbusではない可能性)"}}
            resp_len = int.from_bytes(header[4:6], "big")
            rest = _recv_exact(s, max(0, resp_len - 1), timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    if not rest:
        return {"status": "success", "result": {"banner": "PDU応答がありません"}}
    fc = rest[0]
    if fc == 0x03 and len(rest) >= 2:
        byte_count = rest[1]
        reg_bytes = rest[2:2 + byte_count]
        value = int.from_bytes(reg_bytes[:2], "big") if len(reg_bytes) >= 2 else None
        return {"status": "success", "result": {"banner": "Modbus応答(レジスタ0の値: %s)" % value}}
    if fc == 0x83 and len(rest) >= 2:
        exc = rest[1]
        return {"status": "success", "result": {
            "banner": "Modbus例外応答(本物のModbusサーバーの可能性): " + MODBUS_EXCEPTIONS.get(exc, "code=%d" % exc)}}
    return {"status": "success", "result": {"banner": "Modbus応答として解釈できませんでした(別プロトコルの可能性)",
                                             "raw_hex": rest[:20].hex()}}


def _bson_cstring(s):
    return s.encode("utf-8") + b"\x00"


def _bson_int32(name, value):
    return b"\x10" + _bson_cstring(name) + value.to_bytes(4, "little", signed=True)


def _bson_string(name, value):
    sval = value.encode("utf-8") + b"\x00"
    return b"\x02" + _bson_cstring(name) + len(sval).to_bytes(4, "little") + sval


def _bson_doc(elements):
    body = b"".join(elements) + b"\x00"
    return (len(body) + 4).to_bytes(4, "little") + body


def grab_mongodb(ip, port, timeout):
    """MongoDBのワイヤープロトコル(OP_MSG、opcode 2013)で'hello'コマンドを送る(MongoDBの全クライ
    アントが接続時に送るのと同じ最初の1往復)。応答のBSON本体は完全にはデコードせず、印字可能な
    文字列を簡易抽出する。認証やクエリは行わない。"""
    doc = _bson_doc([_bson_int32("hello", 1), _bson_string("$db", "admin")])
    body = b"\x00\x00\x00\x00" + b"\x00" + doc  # flagBits(4) + section kind0 + BSONドキュメント
    header = (len(body) + 16).to_bytes(4, "little") + (1).to_bytes(4, "little") + \
        (0).to_bytes(4, "little") + (2013).to_bytes(4, "little")
    packet = header + body
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(packet)
            resp_header = _recv_exact(s, 16, timeout)
            if len(resp_header) < 16:
                return {"status": "success",
                        "result": {"banner": "応答が短すぎます(MongoDBではない可能性)"}}
            msg_len = int.from_bytes(resp_header[0:4], "little")
            opcode = int.from_bytes(resp_header[12:16], "little")
            rest = _recv_exact(s, max(0, msg_len - 16), timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    if opcode != 2013:
        return {"status": "success", "result": {"banner": "OP_MSG以外の応答(opcode=%d)" % opcode}}
    doc_bytes = rest[5:] if len(rest) >= 5 else b""
    printable = _extract_printable(doc_bytes)
    return {"status": "success", "result": {
        "banner": "MongoDB hello応答(簡易抽出): " + (printable or "(印字可能な文字列なし)")}}


def _tds_prelogin_packet():
    options = [
        (0x00, b"\x00\x00\x00\x00\x00\x00"),  # VERSION
        (0x01, bytes([0x02])),                 # ENCRYPTION = ENCRYPT_NOT_SUP(TLSへは昇格しない)
        (0x02, b"\x00"),                        # INSTOPT(空のインスタンス名)
        (0x03, b"\x00\x00\x00\x00"),            # THREADID
        (0x04, bytes([0x00])),                  # MARS = OFF
    ]
    token_list, data_blob = b"", b""
    offset = 5 * len(options) + 1
    for token, data in options:
        token_list += bytes([token]) + offset.to_bytes(2, "big") + len(data).to_bytes(2, "big")
        data_blob += data
        offset += len(data)
    token_list += bytes([0xFF])
    payload = token_list + data_blob
    total_len = 8 + len(payload)
    header = bytes([0x12, 0x01]) + total_len.to_bytes(2, "big") + b"\x00\x00" + bytes([0x01, 0x00])
    return header + payload


def grab_mssql(ip, port, timeout):
    """TDSプロトコルのPRELOGINパケット(MS-TDS)を送り、サーバーのバージョンを読み取る。
    ENCRYPTION=ENCRYPT_NOT_SUPを指定し、TLSへの昇格は行わない。ログオンやクエリは行わない。
    実機(本物のSQL Server)での検証はできておらず、自作の模擬応答での自己テストのみ。"""
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(_tds_prelogin_packet())
            header = _recv_exact(s, 8, timeout)
            if len(header) < 8 or header[0] != 0x04:
                return {"status": "success", "result": {"banner": "TDS応答として解釈できませんでした"
                                                          "(MSSQLではない可能性)", "raw_hex": header.hex()}}
            total_len = int.from_bytes(header[2:4], "big")
            rest = _recv_exact(s, max(0, total_len - 8), timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    pos, version_bytes = 0, None
    while pos + 5 <= len(rest) and rest[pos] != 0xFF:
        token = rest[pos]
        opt_offset = int.from_bytes(rest[pos + 1:pos + 3], "big")
        opt_len = int.from_bytes(rest[pos + 3:pos + 5], "big")
        if token == 0x00 and opt_len >= 4:
            version_bytes = rest[opt_offset:opt_offset + 4]
        pos += 5
    if version_bytes and len(version_bytes) >= 4:
        ver = "%d.%d.%d" % (version_bytes[0], version_bytes[1], int.from_bytes(version_bytes[2:4], "big"))
        return {"status": "success", "result": {"banner": "MSSQL PRELOGIN応答(サーバーバージョン: %s)" % ver}}
    return {"status": "success", "result": {"banner": "MSSQL PRELOGIN応答を受信(バージョン抽出に失敗)"}}


TNS_TYPES = {1: "CONNECT", 2: "ACCEPT", 4: "REFUSE", 5: "ACK", 6: "REDIRECT", 7: "DATA",
             9: "RESEND", 11: "MARKER", 12: "ATTENTION", 13: "CONTROL"}


def _tns_connect_packet(host, port, service_name="ORCL"):
    descriptor = ("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=%s))"
                  "(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d)))") % (service_name, host, port)
    cd = descriptor.encode("ascii")
    body = (
        (0x0139).to_bytes(2, "big") + (0x0100).to_bytes(2, "big") +
        (0x0001).to_bytes(2, "big") + (0x0800).to_bytes(2, "big") + (0x7FFF).to_bytes(2, "big") +
        (0x4E54).to_bytes(2, "big") + (0x0001).to_bytes(2, "big") + (0x0000).to_bytes(2, "big") +
        len(cd).to_bytes(2, "big") + (58).to_bytes(2, "big") + (0).to_bytes(4, "big") +
        bytes([0x00, 0x00]) + b"\x00" * 8
    ) + cd
    total_len = 8 + len(body)
    header = total_len.to_bytes(2, "big") + b"\x00\x00" + bytes([0x01, 0x00]) + b"\x00\x00"
    return header + body


def grab_oracle(ip, port, timeout):
    """OracleのTNSプロトコルのCONNECTパケット(接続記述子を含む)を送り、応答のパケット種別
    (ACCEPT/REFUSE等)だけを見る。認証やクエリは行わない。実機(本物のOracle Database)での検証は
    できておらず、自作の模擬応答での自己テストのみ。"""
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(_tns_connect_packet(ip, port))
            header = _recv_exact(s, 8, timeout)
            if len(header) < 8:
                return {"status": "success", "result": {"banner": "応答が短すぎます(Oracleではない可能性)"}}
            total_len = int.from_bytes(header[0:2], "big")
            pkt_type = header[4]
            rest = _recv_exact(s, max(0, total_len - 8), timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    name = TNS_TYPES.get(pkt_type, "0x%02x" % pkt_type)
    extra = ""
    if pkt_type == 4 and rest:  # REFUSE: しばしば理由の文字列を含む
        printable = _extract_printable(rest)
        if printable:
            extra = "(理由: %s)" % printable
    return {"status": "success", "result": {"banner": "TNS応答タイプ: %s%s" % (name, extra)}}


def _pptp_scc_request():
    hostname = b"vt-lite-probe".ljust(64, b"\x00")
    vendor = b"vuln_triage multi_proto_lite".ljust(64, b"\x00")
    body = (
        (1).to_bytes(2, "big") + (0x1A2B3C4D).to_bytes(4, "big") + (1).to_bytes(2, "big") +
        (0).to_bytes(2, "big") + (0x0100).to_bytes(2, "big") + bytes([0, 0]) +
        (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + (0).to_bytes(2, "big") + (0).to_bytes(2, "big") +
        hostname + vendor
    )
    return (len(body) + 2).to_bytes(2, "big") + body


def grab_pptp(ip, port, timeout):
    """PPTPのStart-Control-Connection-Request(RFC 2637)を送り、応答のコントロールメッセージ種別
    を見る。VPNトンネル自体は確立しない。実機(本物のPPTPサーバー)での検証はできておらず、自作の
    模擬応答での自己テストのみ(PPTPは既に広く非推奨の古いプロトコル)。"""
    try:
        with _connect(ip, port, timeout) as s:
            s.sendall(_pptp_scc_request())
            header = _recv_exact(s, 8, timeout)
            if len(header) < 8:
                return {"status": "success", "result": {"banner": "応答が短すぎます(PPTPではない可能性)"}}
            total_len = int.from_bytes(header[0:2], "big")
            rest = _recv_exact(s, max(0, total_len - 8), timeout)
    except OSError as e:
        return _conn_error(e, timeout)
    # header=length(2)+PPTP_MESSAGE_TYPE(2)+MagicCookie(4)。Control Message Typeはrestの先頭2バイト。
    if len(rest) < 2:
        return {"status": "success", "result": {"banner": "応答が短すぎます(PPTPではない可能性)"}}
    ctrl_type = int.from_bytes(rest[0:2], "big")
    names = {2: "Start-Control-Connection-Reply", 3: "Stop-Control-Connection-Request"}
    name = names.get(ctrl_type, "0x%x" % ctrl_type)
    result_code = rest[6] if len(rest) >= 7 else None
    return {"status": "success", "result": {
        "banner": "PPTP応答(%s、result code: %s)" % (name, result_code)}}


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
    "mongodb": lambda ip, port, timeout, host: grab_mongodb(ip, port, timeout),
    "mssql": lambda ip, port, timeout, host: grab_mssql(ip, port, timeout),
    "oracle": lambda ip, port, timeout, host: grab_oracle(ip, port, timeout),
    "smb": lambda ip, port, timeout, host: grab_smb(ip, port, timeout),
    "rdp": lambda ip, port, timeout, host: grab_rdp(ip, port, timeout),
    "snmp": lambda ip, port, timeout, host: grab_snmp(ip, port, timeout),
    "mqtt": lambda ip, port, timeout, host: grab_mqtt(ip, port, timeout),
    "amqp": lambda ip, port, timeout, host: grab_amqp(ip, port, timeout),
    "ipp": lambda ip, port, timeout, host: grab_ipp(ip, port, timeout, host=host),
    "socks5": lambda ip, port, timeout, host: grab_socks5(ip, port, timeout),
    "pptp": lambda ip, port, timeout, host: grab_pptp(ip, port, timeout),
    "modbus": lambda ip, port, timeout, host: grab_modbus(ip, port, timeout),
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
    if a.module in UNVERIFIED_AGAINST_REAL_SERVER:
        print("注意: %s は実機での検証ができておらず、自作の模擬応答での自己テストのみです。"
              "実機での結果と異なる可能性があります。" % a.module, file=sys.stderr)

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
