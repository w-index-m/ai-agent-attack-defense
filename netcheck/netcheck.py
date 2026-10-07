#!/usr/bin/env python3
"""netcheck: 自社の IP・ホストに対する「確認だけ」のチェックツール(ブラウザ画面つき)

やること(読み取りだけ):
  - TCP で接続できるポートの一覧 / 接続時の表示(バナー)の読み取り
  - HTTP の通常の応答ヘッダ、HTTPS 証明書の状態
  - 管理画面らしき URL が応答するか(状態コードを見るだけ。ログインはしない)
やらないこと:
  - 脆弱性を突く動作(SQL インジェクションの試行、総当たり、アップロード等)
  - データの読み出し・変更、権限の昇格

安全のための制限:
  - 対象は、許可した IP 範囲(既定: 社内のプライベート IP)だけ。範囲外は実行を拒否する
  - 画面は 127.0.0.1 だけで待ち受け、起動のたびに変わる合言葉(トークン)が必要
  - 実行のたびに「自社が管理している対象」の確認が必要。実行は netcheck.log に記録する
標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse, concurrent.futures as cf, http.client, ipaddress, json, os, re, secrets
import socket, ssl, sys, threading, time, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, "netcheck.log")
UA = "netcheck/1.0 (internal asset check; read-only)"

DEFAULT_ALLOWED = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
STANDARD_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
                  2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 11211, 27017,
                  2375, 2376, 11434]
EXTENDED_PORTS = sorted(set(STANDARD_PORTS + [81, 88, 389, 636, 1521, 5000, 5601, 5985, 7001,
                                              8081, 8181, 9000, 9090, 15672,
                                              1234, 2379, 4646, 6443, 8500, 10250,
                                              902, 5480, 9443]))
HTTP_PORTS = {80, 81, 3000, 5000, 5601, 7001, 8000, 8080, 8081, 8181, 8888, 9000, 9090, 9200, 15672,
              1234, 4646, 8500, 11434}
HTTPS_PORTS = {443, 8443, 5480, 9443}
BANNER_PORTS = {21, 22, 25, 110, 143, 3306}
ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
               "/manager/html", "/login", "/console"]

# ポートごとの注意(sev, 題名, 説明, 直し方)
RISKY = {
    21: ("medium", "FTP が開いている", "FTP は通信が暗号化されません。", "SFTP/FTPS に切り替えるか、不要なら閉じる。"),
    23: ("high", "Telnet が開いている", "Telnet は通信が暗号化されず、認証情報が見えます。", "SSH に切り替え、Telnet は停止する。"),
    111: ("medium", "rpcbind が開いている", "NFS などの共有の入口です。", "不要なら停止し、必要なら接続元を限定する。"),
    135: ("medium", "Windows RPC が開いている", "社内向けの機能です。", "接続元を限定する。"),
    139: ("medium", "NetBIOS が開いている", "社内向けの機能です。", "接続元を限定する。"),
    445: ("medium", "SMB が開いている", "ファイル共有の入口で、攻撃の対象になりやすいポートです。", "接続元を限定し、更新を適用する。"),
    1433: ("high", "SQL Server が開いている", "データベースが、ネットワークから直接届く状態です。", "アプリのサーバーだけから接続できるようにする。"),
    1521: ("high", "Oracle DB が開いている", "データベースが、ネットワークから直接届く状態です。", "アプリのサーバーだけから接続できるようにする。"),
    2049: ("high", "NFS が開いている", "NFS の設定不備(no_root_squash など)は、今回の攻撃連鎖の一段でした。", "/etc/exports で no_root_squash を外し、接続元を限定する。"),
    2375: ("critical", "Docker API(暗号化なし)が開いている", "認証なしで、コンテナの操作ができる可能性があります。", "直ちに閉じる。必要なら TLS と認証を付ける。"),
    3306: ("high", "MySQL が開いている", "データベースが、ネットワークから直接届く状態です。", "アプリのサーバーだけから接続できるようにする。"),
    3389: ("high", "リモートデスクトップが開いている", "総当たりやリモートの欠陥の標的になりやすいポートです。", "VPN の内側に置き、多要素認証を付ける。"),
    5432: ("high", "PostgreSQL が開いている", "データベースが、ネットワークから直接届く状態です。", "アプリのサーバーだけから接続できるようにする。"),
    5900: ("high", "VNC が開いている", "画面の遠隔操作です。", "VPN の内側に置き、強い認証を付ける。"),
    6379: ("high", "Redis が開いている", "認証なしで使えることが多く、データの読み書きができます。", "接続元を限定し、パスワードを設定する。"),
    9200: ("high", "Elasticsearch が開いている", "認証なしで、データを読めることがあります。", "接続元を限定し、認証を有効にする。"),
    11211: ("high", "memcached が開いている", "認証がなく、データの読み出しや攻撃への悪用があります。", "接続元を限定する。"),
    27017: ("high", "MongoDB が開いている", "認証なしで、データを読めることがあります。", "接続元を限定し、認証を有効にする。"),
    # --- コンテナ / オーケストレーション（露出するとコンテナ奪取・クラスタ侵害に直結）---
    2376: ("high", "Docker API(TLS)が開いている", "TLS でも、証明書/認証が緩いと外からコンテナ操作ができます。", "接続元を限定し、クライアント証明書認証を必須にする。"),
    2379: ("high", "etcd が開いている", "Kubernetes のデータストア。クラスタの秘密情報が読まれる恐れがあります。", "接続元を限定し、認証・TLS を必須にする。"),
    6443: ("high", "Kubernetes API が開いている", "クラスタの制御面です。設定不備で乗っ取りに直結します。", "接続元を限定し、匿名アクセスを無効化、RBAC を徹底する。"),
    10250: ("high", "kubelet API が開いている", "ノード上のコンテナ操作の入口になり得ます。", "接続元を限定し、匿名・読み取り専用ポートを無効化する。"),
    8500: ("high", "Consul が開いている", "サービス構成・鍵が読まれる恐れがあります。", "接続元を限定し、ACL を有効にする。"),
    4646: ("medium", "Nomad が開いている", "ジョブ実行基盤の制御面です。", "接続元を限定し、ACL を有効にする。"),
    5000: ("medium", "レジストリ/開発サーバが開いている(5000)", "Docker レジストリや開発用サーバが外から届く状態のことがあります。", "本番で不要なら閉じ、必要なら認証と接続元制限を付ける。"),
    # --- LLM 推論 API の露出（R1 の“egress/推論の口”が外から直接叩ける状態）---
    11434: ("high", "ローカルLLM API(Ollama等)が開いている", "認証なしで外から推論を実行・悪用され得ます。R1(LLM egress)の裏返しで、推論の口が露出している状態。", "localhost/VPN 内に限定し、CORS/接続元を絞る。公開しない。"),
    1234: ("medium", "ローカルLLM API(LM Studio等)が開いている", "認証なしで外から推論を実行され得ます。", "localhost/VPN 内に限定する。公開しない。"),
    # --- 管理/監視ダッシュボード（偵察の標的。R3 相当の露出）---
    5601: ("medium", "Kibana が開いている", "ログ閲覧の管理画面が外から届く状態です(偵察の標的)。", "認証を必須にし、接続元を限定する。"),
    15672: ("medium", "RabbitMQ 管理画面が開いている", "キュー基盤の管理画面が外から届く状態です。", "既定認証を変更し、接続元を限定する。"),
    9090: ("low", "Prometheus が開いている", "メトリクスから内部構成が読まれ、偵察に使われ得ます。", "接続元を限定し、認証を前段に置く。"),
    3000: ("low", "Grafana/開発サーバが開いている(3000)", "ダッシュボードや開発サーバが外から届く状態のことがあります。", "認証を必須にし、接続元を限定する。"),
    # --- 仮想基盤の管理面（vCenter / ESXi / 管理アプライアンス）---
    # 認証なしの既知 Critical（例: VMSA-2026-0006 の vCenter unauth RCE, 最大 CVSS 9.8）の標的になり得る。
    # netcheck は“露出の有無”だけを確認する。実際の脆弱性有無はベンダのアドバイザリとパッチ状況で判断すること。
    902: ("high", "ESXi の管理ポート(902)が開いている", "ハイパーバイザ(ESXi)の管理面がネットワークから届く状態です。仮想基盤の管理面は、認証回避の既知 Critical の標的になりやすい層です。", "管理用の隔離ネットワーク/VPN の内側に限定し、ベンダのアドバイザリに従って最新パッチを適用する。"),
    5480: ("high", "管理アプライアンス UI(5480/VAMI)が開いている", "vCenter などのアプライアンス管理 UI が外から届く状態です(偵察・攻撃の標的)。", "管理ネットワーク/VPN 内に限定し、認証を必須にして最新パッチを適用する。"),
    9443: ("medium", "vSphere 管理 UI(9443)が開いている", "仮想基盤の管理 UI/プラグイン面が外から届く状態です(偵察の標的)。", "管理ネットワーク/VPN 内に限定し、最新パッチを適用する。"),
}

# ポート→関連する検知/防御の参照(R1–R7 / ③予防)。netcheck は“露出(攻撃面)”を観測し、
# それが防御側のどのルール/コントロールに対応するかをタグで示す。詳細は
# security-scan/defense-detection-notes.md を参照。
PORT_RULE = {
    # コンテナ/オーケストレーション → R2(特権/コンテナ露出)
    2375: "R2", 2376: "R2", 2379: "R2", 6443: "R2", 10250: "R2", 8500: "R2", 4646: "R2",
    # LLM 推論 API の露出 → R1(LLM egress/推論の口)
    11434: "R1", 1234: "R1",
    # 管理/監視ダッシュボード・開発サーバ → R3(偵察の標的)
    5601: "R3", 15672: "R3", 9090: "R3", 3000: "R3", 5000: "R3",
    # 仮想基盤の管理面 → 管理UIは R3(偵察の標的)、ハイパーバイザ直の口は ③(攻撃面最小化)
    5480: "R3", 9443: "R3", 902: "③",
    # DB/サービスのネット直結露出 → ③攻撃面最小化
    1433: "③", 1521: "③", 3306: "③", 5432: "③", 6379: "③", 9200: "③",
    11211: "③", 27017: "③", 2049: "③",
    # 平文/旧式プロトコル・遠隔操作 → ③最小露出・堅牢化
    21: "③", 23: "③", 111: "③", 135: "③", 139: "③", 445: "③", 3389: "③", 5900: "③",
}
EOL_HINTS = [  # (正規表現, 説明)
    (re.compile(r"PHP/(5|7)\.", re.I), "PHP 5/7 系はサポートが終了しています"),
    (re.compile(r"Apache/2\.(0|2)\.", re.I), "Apache 2.0/2.2 系はサポートが終了しています"),
    (re.compile(r"Microsoft-IIS/(6|7|8)\.", re.I), "この IIS のバージョンはサポートが終了しています"),
    (re.compile(r"OpenSSH_[1-6]\.", re.I), "OpenSSH 6 以前は古いバージョンです"),
]
SQLI_NOTE = ("SQL インジェクションの有無は、この確認では分かりません。サイト固有のコードの問題なので、"
             "Semgrep などのコード診断、または許可を得た検証環境での診断で確認してください。")


class TooMany(Exception):
    pass


def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def log(line):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write("%s %s\n" % (now(), line))
    except OSError:
        pass


def load_config():
    cfg = {"allowed_ranges": [], "max_targets": 256, "port_timeout": 1.0, "delay": 0.02}
    p = os.path.join(HERE, "config.json")
    if os.path.exists(p):
        try:
            cfg.update(json.load(open(p, encoding="utf-8")))
        except (OSError, ValueError) as e:
            print("config.json を読めませんでした:", e, file=sys.stderr)
    return cfg


def allowed_networks(cfg):
    return [ipaddress.ip_network(x, strict=False) for x in DEFAULT_ALLOWED + list(cfg.get("allowed_ranges", []))]


def expand_targets(text, cfg):
    """入力(IP / CIDR / ホスト名)を、(表示名, IP)のリストにする。範囲外は拒否する。"""
    nets = allowed_networks(cfg)
    out, refused = [], []
    for raw in re.split(r"[\s,]+", text.strip()):
        if not raw:
            continue
        try:
            if "/" in raw:
                net = ipaddress.ip_network(raw, strict=False)
                if net.num_addresses > cfg["max_targets"] + 2:
                    raise TooMany("対象が多すぎます(上限 %d)。範囲を小さくしてください。" % cfg["max_targets"])
                hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
                for h in hosts:
                    out.append((str(h), str(h)))
            else:
                try:
                    out.append((raw, str(ipaddress.ip_address(raw))))
                except ValueError:
                    ips = {ai[4][0] for ai in socket.getaddrinfo(raw, None, socket.AF_UNSPEC, socket.SOCK_STREAM)}
                    for ip in sorted(ips):
                        out.append((raw, ip))
        except (ValueError, socket.gaierror):
            refused.append("%s(解釈できません)" % raw)
        if len(out) > cfg["max_targets"]:
            raise TooMany("対象が多すぎます(上限 %d)。範囲を小さくしてください。" % cfg["max_targets"])
    ok = []
    for name, ip in out:
        addr = ipaddress.ip_address(ip)
        if any(addr in n for n in nets if n.version == addr.version):
            ok.append((name, ip))
        else:
            refused.append("%s → %s(許可した範囲の外)" % (name, ip))
    return ok, refused


def tcp_open(ip, port, timeout):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return s
    except OSError:
        s.close()
        return None


def read_banner(s):
    try:
        s.settimeout(1.5)
        data = s.recv(256)
        return data.decode("latin-1", "replace").strip().splitlines()[0][:160] if data else ""
    except OSError:
        return ""


def http_get(ip, port, host, path, tls, method="GET", timeout=3.0):
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # ここは応答を読むだけ。証明書の検証は別に行う
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request(method, path, headers={"Host": host, "User-Agent": UA, "Connection": "close"})
        r = conn.getresponse()
        r.read(2048)
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie"]
        conn.close()
        return r.status, hdrs, cookies
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return None, {}, []


def tls_info(ip, port, timeout=3.0):
    """証明書を、鎖と期限だけ検証して読む(名前の照合はしない)。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as s:
                cert = s.getpeercert()
                exp = ssl.cert_time_to_seconds(cert["notAfter"])
                days = int((exp - time.time()) // 86400)
                return {"ok": True, "version": s.version(), "days_left": days,
                        "subject": dict(x[0] for x in cert.get("subject", ()))}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "reason": e.verify_message or str(e)}
    except (OSError, ssl.SSLError) as e:
        return {"ok": None, "reason": str(e)}


def add(findings, sev, title, detail, fix, port=None, r=""):
    findings.append({"sev": sev, "title": title, "detail": detail, "fix": fix, "port": port, "r": r})


def check_host(name, ip, ports, cfg, admin_check, progress):
    res = {"name": name, "ip": ip, "open": [], "findings": [], "http": [], "admin": []}
    f = res["findings"]
    timeout = float(cfg["port_timeout"])
    delay = float(cfg["delay"])
    socks = {}

    def probe(p):
        time.sleep(delay)
        s = tcp_open(ip, p, timeout)
        if s:
            socks[p] = s
        progress()
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(probe, ports))

    for p in sorted(socks):
        s = socks[p]
        banner = read_banner(s) if p in BANNER_PORTS else ""
        s.close()
        res["open"].append({"port": p, "banner": banner})
        if p in RISKY:
            sev, t, d, fx = RISKY[p]
            add(f, sev, t, d, fx, p, PORT_RULE.get(p, ""))
        for rx, msg in EOL_HINTS:
            if banner and rx.search(banner):
                add(f, "medium", "古いバージョンの可能性(%s)" % banner, msg, "サポート中のバージョンに更新する。", p, "R3")
        if p in BANNER_PORTS and banner:
            add(f, "info", "接続時にバージョン情報が見える(ポート %d)" % p, banner, "不要な情報は表示しない設定にする。", p, "R3")

    open_ports = {o["port"] for o in res["open"]}
    for p in sorted(open_ports & (HTTP_PORTS | HTTPS_PORTS)):
        tls = p in HTTPS_PORTS
        status, h, cookies = http_get(ip, p, name, "/", tls)
        if status is None:
            continue
        info = {"port": p, "tls": tls, "status": status, "server": h.get("server", "")}
        res["http"].append(info)
        srv = " ".join(x for x in (h.get("server", ""), h.get("x-powered-by", "")) if x)
        if re.search(r"\d+\.\d+", srv):
            add(f, "low", "応答にバージョン情報が出ている(ポート %d)" % p, srv, "Server / X-Powered-By のバージョン表示を消す。", p, "R3")
        for rx, msg in EOL_HINTS:
            if srv and rx.search(srv):
                add(f, "medium", "古いバージョンの可能性(%s)" % srv, msg, "サポート中のバージョンに更新する。", p, "R3")
        if "content-security-policy" not in h:
            add(f, "medium", "CSP がない(ポート %d)" % p,
                "他人のスクリプトの実行を制限する設定がありません。決済ページでは、カード窃取コードの挿入を防ぐ要になります。",
                "まず Content-Security-Policy-Report-Only で、読み込み元を洗い出してから、CSP を有効にする。", p, "③CSP")
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            add(f, "low", "クリックジャッキング対策のヘッダがない(ポート %d)" % p, "他のサイトに埋め込まれて操作される可能性があります。",
                "X-Frame-Options か、CSP の frame-ancestors を設定する。", p)
        if "x-content-type-options" not in h:
            add(f, "low", "X-Content-Type-Options がない(ポート %d)" % p, "", "X-Content-Type-Options: nosniff を設定する。", p)
        if tls and "strict-transport-security" not in h:
            add(f, "low", "HSTS がない(ポート %d)" % p, "", "Strict-Transport-Security を設定する。", p)
        for c in cookies:
            low = c.lower()
            miss = [x for x, k in (("Secure", "secure"), ("HttpOnly", "httponly")) if k not in low]
            if miss and (tls or "secure" not in low):
                add(f, "low", "Cookie の属性が足りない(ポート %d)" % p, "%s に %s がない" % (c.split("=")[0], "・".join(miss)),
                    "Secure と HttpOnly(必要なら SameSite)を付ける。", p)
        if tls:
            t = tls_info(ip, p)
            info["tls_info"] = t
            if t.get("ok") is True:
                if t["days_left"] < 0:
                    add(f, "high", "HTTPS 証明書の期限が切れている(ポート %d)" % p, "", "証明書を更新する。", p)
                elif t["days_left"] < 30:
                    add(f, "medium", "HTTPS 証明書の期限が近い(残り %d 日)" % t["days_left"], "", "証明書を更新する(自動更新が望ましい)。", p)
                if t.get("version") in ("TLSv1", "TLSv1.1"):
                    add(f, "high", "古い TLS が使われている(%s)" % t["version"], "", "TLS 1.2 以上に限定する。", p)
            elif t.get("ok") is False:
                add(f, "medium", "HTTPS 証明書を検証できない(ポート %d)" % p, t.get("reason", ""),
                    "信頼された認証局の証明書にするか、社内の認証局を正しく配布する。期限切れの場合は更新する。", p)
        if admin_check:
            for path in ADMIN_PATHS:
                time.sleep(delay)
                st, _, _ = http_get(ip, p, name, path, tls, timeout=3.0)
                if st is not None and st != 404:
                    res["admin"].append({"port": p, "path": path, "status": st})
                    if st in (200, 401):
                        add(f, "medium", "管理画面らしき URL が応答している: %s(ポート %d, 状態 %d)" % (path, p, st),
                            "ログインはせず、応答の状態だけを見ています。",
                            "社内ネットワークや VPN、IP 制限の内側に置き、多要素認証を付ける。", p, "R3")
                    elif st in (301, 302, 303, 307, 308):
                        add(f, "info", "管理画面らしき URL がリダイレクトされる: %s(ポート %d)" % (path, p), "", "公開が必要か確認する。", p, "R3")
    res["findings"].sort(key=lambda x: ["critical", "high", "medium", "low", "info"].index(x["sev"]))
    return res


JOBS = {}


def run_job(job_id, targets, ports, admin, cfg):
    job = JOBS[job_id]
    total = len(targets) * len(ports)
    state = {"done": 0}
    lock = threading.Lock()

    def progress():
        with lock:
            state["done"] += 1
            job["progress"] = min(0.99, state["done"] / max(1, total))
    try:
        for name, ip in targets:
            job["current"] = "%s (%s)" % (name, ip)
            job["results"].append(check_host(name, ip, ports, cfg, admin, progress))
        job["status"] = "done"
    except Exception as e:  # noqa
        job["status"] = "error"
        job["error"] = str(e)
    job["progress"] = 1.0
    job["finished"] = now()
    log("job=%s 完了 hosts=%d" % (job_id, len(job["results"])))


def start_scan(body, cfg):
    if body.get("consent") is not True:
        return 400, {"error": "「自社が管理している対象です」の確認が必要です。"}
    try:
        targets, refused = expand_targets(str(body.get("targets", "")), cfg)
    except TooMany as e:
        return 400, {"error": str(e)}
    if refused:
        log("拒否 %s" % "; ".join(refused))
        return 400, {"error": "許可した範囲の外、または解釈できない対象があります。実行しません。", "refused": refused}
    if not targets:
        return 400, {"error": "対象を入力してください。"}
    ports = EXTENDED_PORTS if body.get("ports") == "extended" else STANDARD_PORTS
    admin = bool(body.get("admin", True))
    job_id = uuid.uuid4().hex[:10]
    JOBS[job_id] = {"id": job_id, "status": "running", "progress": 0.0, "current": "", "started": now(),
                    "results": [], "targets": [t[1] for t in targets], "sqli_note": SQLI_NOTE}
    log("job=%s 開始 consent=true targets=%s ports=%s admin=%s" % (job_id, ",".join(t[1] for t in targets), body.get("ports", "standard"), admin))
    threading.Thread(target=run_job, args=(job_id, targets, ports, admin, cfg), daemon=True).start()
    return 200, {"id": job_id, "count": len(targets)}


class Handler(BaseHTTPRequestHandler):
    server_version = "netcheck"
    cfg = {}
    token = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline' 'self'; script-src 'unsafe-inline' 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _auth(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            return False
        return secrets.compare_digest(self.headers.get("X-Token", ""), self.token)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            q = parse_qs(u.query)
            if not secrets.compare_digest(q.get("t", [""])[0], self.token):
                return self._send(403, "起動時に表示された URL(?t=...付き)から開いてください。".encode("utf-8"), "text/plain; charset=utf-8")
            return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        if not self._auth():
            return self._send(403, {"error": "認証に失敗しました。"})
        if u.path == "/api/job":
            j = JOBS.get(parse_qs(u.query).get("id", [""])[0])
            return self._send(200 if j else 404, j or {"error": "見つかりません"})
        if u.path == "/api/config":
            return self._send(200, {"allowed": [str(n) for n in allowed_networks(self.cfg)], "max_targets": self.cfg["max_targets"]})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth() or self.path != "/api/scan":
            return self._send(403, {"error": "認証に失敗しました。"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
        except (ValueError, OSError):
            return self._send(400, {"error": "リクエストを読めませんでした。"})
        code, out = start_scan(body, self.cfg)
        self._send(code, out)


PAGE = r"""<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>netcheck</title><style>
:root{--bg:#f3f6f6;--sf:#fff;--s2:#e9eff0;--ln:#d3dcde;--fg:#18262b;--mu:#566a71;--ac:#0f6f68;--acf:#fff;--crit:#a3262a;--high:#c0511d;--med:#a57400;--low:#3f6f94;--info:#6b7b82;
--cb:#f8e3e3;--hb:#fbe9dd;--mb:#f8efd2;--lb:#e1ecf5;--ib:#e8edee}
@media(prefers-color-scheme:dark){:root{--bg:#10191c;--sf:#172326;--s2:#1f2f33;--ln:#2c4045;--fg:#e3eef0;--mu:#97aeb4;--ac:#4fc3b8;--acf:#06211f;--crit:#ff8f8f;--high:#ffa070;--med:#e8c25a;--low:#86b9e3;--info:#9db0b6;--cb:#3a1b1d;--hb:#3a2417;--mb:#352d12;--lb:#17293a;--ib:#222f33;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.7 system-ui,-apple-system,"Hiragino Sans","Yu Gothic",sans-serif;padding:20px 16px 48px}
.w{max-width:960px;margin:auto;display:flex;flex-direction:column;gap:20px}h1{margin:0;font-size:24px}h2{margin:0;font-size:16px}
.p{background:var(--sf);border:1px solid var(--ln);border-radius:6px;padding:16px;display:flex;flex-direction:column;gap:12px;min-width:0}
textarea{width:100%;min-height:90px;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--fg);border:1px solid var(--ln);border-radius:4px;padding:8px}
button,select{font:inherit;border:1px solid var(--ln);background:var(--s2);color:var(--fg);border-radius:4px;padding:7px 14px;min-height:36px;cursor:pointer}
button.pr{background:var(--ac);color:var(--acf);border-color:var(--ac);font-weight:600}button:disabled{opacity:.5;cursor:not-allowed}
.r{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.n{color:var(--mu);font-size:12.5px}.err{color:var(--crit);font-weight:600}
.warn{background:var(--mb);color:var(--fg);border-left:4px solid var(--med);padding:10px 12px;border-radius:4px}
.bar{height:8px;background:var(--s2);border-radius:4px;overflow:hidden}.bar i{display:block;height:100%;background:var(--ac);width:0}
.tag{display:inline-block;font-size:11.5px;font-weight:700;padding:1px 8px;border-radius:3px}
.rtag{display:inline-block;font-size:11px;font-weight:700;padding:1px 6px;border-radius:3px;margin-left:6px;border:1px solid var(--ln);color:var(--mu)}
.critical{background:var(--cb);color:var(--crit)}.high{background:var(--hb);color:var(--high)}.medium{background:var(--mb);color:var(--med)}.low{background:var(--lb);color:var(--low)}.info{background:var(--ib);color:var(--info)}
.sv{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px}.sv div{border-radius:4px;padding:6px 10px;display:flex;justify-content:space-between}
details{border:1px solid var(--ln);border-left-width:5px;border-radius:4px;background:var(--sf)}summary{cursor:pointer;padding:8px 12px}
.b{padding:4px 14px 12px;border-top:1px solid var(--ln)}.b h4{margin:8px 0 2px;font-size:12.5px;color:var(--ac)}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--ln);padding:4px 8px;text-align:left;font-size:13px;vertical-align:top}.sc{overflow-x:auto}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
</style></head><body><div class="w">
<header><h1>netcheck</h1><p class="n" style="margin:4px 0 0">自社の IP・ホストに対する、確認だけのチェックです。脆弱性を突く動作はしません。</p></header>
<div class="p"><h2>1. 対象を入力</h2>
<label class="n" for="t">IP、範囲(例: 192.168.1.0/28)、ホスト名を、改行かカンマで区切って入力します。</label>
<textarea id="t" placeholder="192.168.1.10&#10;192.168.1.0/28"></textarea>
<div class="n" id="al"></div>
<div class="r"><label>ポート <select id="pt"><option value="standard">標準(約30)</option><option value="extended">拡張(約45)</option></select></label>
<label><input type="checkbox" id="ad" checked> 管理画面らしき URL の応答も見る(ログインはしない)</label></div>
<label class="warn"><input type="checkbox" id="cs"> 入力した対象は、自社が管理している(または書面で許可を得た)ものです。</label>
<div class="r"><button class="pr" id="go">確認を開始</button><span id="msg" class="n" role="status"></span></div>
<div class="bar" id="bw" hidden><i id="bi"></i></div><div class="n" id="cur"></div></div>
<div class="p" id="out" hidden><h2>2. 結果</h2><div class="sv" id="sv"></div><div id="res"></div>
<div class="warn" id="sq"></div><div class="r"><button id="ex">結果を JSON で保存</button></div></div>
</div><script>
var TOKEN=new URLSearchParams(location.search).get("t")||"",job=null,last=null;
var $=function(i){return document.getElementById(i)};
var SEV=["critical","high","medium","low","info"],LB={critical:"緊急",high:"高",medium:"中",low:"低",info:"情報"};
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function api(p,o){o=o||{};o.headers=Object.assign({"X-Token":TOKEN,"Content-Type":"application/json"},o.headers||{});return fetch(p,o).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})})}
api("/api/config").then(function(r){if(r.ok)$("al").textContent="許可している範囲: "+r.j.allowed.join(" , ")+"(範囲外は実行しません。追加は config.json で行います)"});
$("go").onclick=function(){
  $("msg").className="n";$("msg").textContent="";
  if(!$("cs").checked){$("msg").className="err";$("msg").textContent="確認のチェックを入れてください。";return}
  api("/api/scan",{method:"POST",body:JSON.stringify({targets:$("t").value,ports:$("pt").value,admin:$("ad").checked,consent:true})}).then(function(r){
    if(!r.ok){$("msg").className="err";$("msg").textContent=r.j.error+(r.j.refused?" "+r.j.refused.join(" / "):"");return}
    job=r.j.id;$("go").disabled=true;$("bw").hidden=false;$("out").hidden=true;poll();
  });
};
function poll(){api("/api/job?id="+job).then(function(r){var j=r.j;last=j;
  $("bi").style.width=Math.round(j.progress*100)+"%";$("cur").textContent=j.status==="running"?"確認中: "+j.current:"";
  if(j.status==="running"){setTimeout(poll,800);return}
  $("go").disabled=false;$("bw").hidden=true;if(j.status==="error"){$("msg").className="err";$("msg").textContent=j.error;return}render(j)})}
function render(j){
  var c={};SEV.forEach(function(s){c[s]=0});j.results.forEach(function(h){h.findings.forEach(function(f){c[f.sev]++})});
  $("sv").innerHTML=SEV.map(function(s){return'<div class="'+s+'"><span>'+LB[s]+'</span><b>'+c[s]+"</b></div>"}).join("");
  $("res").innerHTML=j.results.map(function(h){
    var op=h.open.length?'<div class="sc"><table><tr><th>ポート</th><th>表示(バナー)</th></tr>'+h.open.map(function(o){return"<tr><td>"+o.port+"</td><td><code>"+esc(o.banner)+"</code></td></tr>"}).join("")+"</table></div>":'<p class="n">開いているポートはありません(応答なし)。</p>';
    var fs=h.findings.map(function(f){return'<details class="'+f.sev+'"><summary><span class="tag '+f.sev+'">'+LB[f.sev]+"</span> "+esc(f.title)+(f.r?'<span class="rtag">'+esc(f.r)+"</span>":"")+'</summary><div class="b">'+(f.detail?"<h4>内容</h4>"+esc(f.detail):"")+"<h4>直し方</h4>"+esc(f.fix)+(f.r?'<h4>関連する検知/防御</h4>'+esc(f.r)+"（security-scan/defense-detection-notes.md）":"")+"</div></details>"}).join("");
    return'<div style="margin-top:14px"><h2>'+esc(h.name)+' <span class="n">'+esc(h.ip)+"</span></h2>"+op+'<div style="display:flex;flex-direction:column;gap:6px;margin-top:8px">'+(fs||'<p class="n">指摘はありません。</p>')+"</div></div>"}).join("");
  $("sq").textContent=j.sqli_note;$("out").hidden=false;
}
$("ex").onclick=function(){if(!last)return;var a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(last,null,2)],{type:"application/json"}));a.download="netcheck-"+last.id+".json";a.click()};
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="netcheck: 確認だけのネットワークチェック(ブラウザ画面)")
    ap.add_argument("--port", type=int, default=8765, help="画面の待ち受けポート(既定 8765)")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    cfg = load_config()
    Handler.cfg = cfg
    Handler.token = secrets.token_urlsafe(16)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    url = "http://127.0.0.1:%d/?t=%s" % (a.port, Handler.token)
    print("netcheck を起動しました。次の URL をブラウザで開いてください(このパソコンだけから開けます):")
    print(url)
    print("許可している範囲:", ", ".join(str(n) for n in allowed_networks(cfg)))
    print("終了は Ctrl+C。実行の記録は", LOG_PATH)
    log("起動 allowed=%s" % ",".join(str(n) for n in allowed_networks(cfg)))
    if not a.no_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:  # noqa
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n終了します。")


if __name__ == "__main__":
    main()
