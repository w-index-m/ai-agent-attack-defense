#!/usr/bin/env python3
"""local_scan_selfcheck: vuln_triage.html の「ローカルスキャナーを呼び出す」が、この端末で
動く状態かをまとめて確認する自己診断(Windows 11 + Docker Desktop + PowerShell を主に想定)。

確認すること:
  1. 環境: Python・OS・文字コード・docker(デーモン起動済みか)・uv・git・各環境変数
  2. ポート: sqli-labデモアプリ(VULN_APP_PORT/VULN_INTERNAL_PORT)・モックLLM(8899)・本サーバー
     (8766)が使えるか。Windowsでは「他のソフトが使用中(WinError 10048)」と「ウイルス対策ソフト等に
     ブロックされている(WinError 10013)」を区別して表示する。
  3. 起動中の local_scan_server.py への疎通(--url): /health、netcheck、HTTPバナー取得(軽量)。
     対象は 127.0.0.1(この端末自身)だけ。--full を付けると Semgrep/Trivy/gitleaks も実行する
     (数分かかる)。Strix/Cairn は実行せず、前提条件(環境変数・uv)の確認だけ行う。

使い方(PowerShell。先に別ウィンドウで local_scan_server.py を起動しておく):
    python scripts\\local_scan_selfcheck.py
    python scripts\\local_scan_selfcheck.py --full
結果は画面に表示し、同じ内容を results\\local-scan\\selfcheck.txt にも保存する(貼り付けて共有用)。
標準ライブラリだけで動く(Python 3.8 以上)。
"""
import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
ROWS = []


def row(status, item, detail):
    ROWS.append((status, item, detail))


def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace").strip()
    except FileNotFoundError:
        return None, "コマンドが見つかりません"
    except subprocess.TimeoutExpired:
        return None, "タイムアウトしました(%d秒)" % timeout


def check_environment():
    v = sys.version_info
    row("OK" if v >= (3, 8) else "NG", "Python", "%s (%s)" % (platform.python_version(), sys.executable))
    row("情報", "OS", "%s %s" % (platform.system(), platform.release()))
    import locale
    enc = locale.getencoding() if hasattr(locale, "getencoding") else locale.getpreferredencoding(False)
    row("情報", "既定の文字コード", "ファイル既定=%s(日本語版Windowsはcp932)" % enc)
    if shutil.which("docker"):
        rc, out = run(["docker", "info", "--format", "{{.ServerVersion}}"])
        if rc == 0:
            row("OK", "Docker", "デーモン稼働中 (Server %s)" % out.splitlines()[-1])
        else:
            row("警告", "Docker", "dockerコマンドはあるがデーモンに繋がりません。Docker Desktopを起動してください。")
    else:
        row("警告", "Docker", "見つかりません(Semgrep/Trivy/gitleaksはローカルのコマンドかDockerが必要)")
    for tool, why in (("uv", "Strix/Cairnに必要"), ("git", "git pull用"), ("semgrep", "無ければDockerで代用"),
                      ("trivy", "無ければDockerで代用"), ("gitleaks", "無ければDockerで代用"),
                      ("zgrab2", "無ければ軽量版ボタンで代用可")):
        row("OK" if shutil.which(tool) else "情報", tool, shutil.which(tool) or "未インストール(%s)" % why)
    for name in ("STRIX_LOCAL_DIR", "CAIRN_LOCAL_DIR"):
        val = os.environ.get(name, "").strip()
        if not val:
            row("情報", name, "未設定(このボタンを使う場合のみ必要)")
        elif os.path.isdir(val):
            row("OK", name, val)
        else:
            row("NG", name, "フォルダが存在しません: %s" % val)
    if os.name == "nt":
        row("情報", "Strix(Windows)", "Windows上のサーバーではStrixボタンは即座にエラーになります(Unix専用の"
            "部品を使うため)。WSL2で別ポート(例: 8767)のサーバーを起動し、画面の「Strix用エンドポイント」に"
            "指定してください。")


def port_state(port):
    """まず接続して「実際に待ち受けているか」を確かめ、待ち受けが無ければbindで使えるかを見る
    (bindだけだと、直前に閉じたソケットのTIME_WAITでも「使用中」と誤判定するため)。"""
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.settimeout(0.5)
    try:
        if c.connect_ex(("127.0.0.1", port)) == 0:
            return "使用中", "待ち受け中のプロセスがあります"
    finally:
        c.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return "空き", None
    except OSError as e:
        code = getattr(e, "winerror", None) or e.errno
        if code == 10013:
            return "ブロック", "WinError 10013: ウイルス対策ソフト等が使用/ブロックしている可能性"
        if code in (10048, 98, 48):
            return "使用中", "直前まで使われていた(しばらく待てば空く)か、別のアドレスで使用中"
        return "不明", str(e)
    finally:
        s.close()


def check_ports(server_port):
    app = int(os.environ.get("VULN_APP_PORT", "5000"))
    internal = int(os.environ.get("VULN_INTERNAL_PORT", "5001"))  # vulnerable_app.pyの既定と同じ
    for port, what in ((app, "sqli-labデモアプリ(VULN_APP_PORT)"), (internal, "デモアプリ内部(VULN_INTERNAL_PORT)"),
                       (8899, "モックLLM(Strix用)"), (server_port, "local_scan_server.py")):
        state, why = port_state(port)
        if port == server_port:
            listening = state == "使用中" and why == "待ち受け中のプロセスがあります"
            row("OK" if listening else "警告", "ポート%d %s" % (port, what),
                "待ち受け中(サーバー起動済みと思われます)" if listening else
                "待ち受けがありません。先に local_scan_server.py を起動してください。")
            continue
        if state == "空き":
            row("OK", "ポート%d %s" % (port, what), "空き")
        else:
            row("警告", "ポート%d %s" % (port, what),
                "%s(%s)。GUIが自動起動したデモアプリが残っているだけなら問題ありません。他のソフトの場合は "
                "$env:VULN_APP_PORT=\"5100\"; $env:VULN_INTERNAL_PORT=\"5101\" を設定してから "
                "local_scan_server.py を起動し直してください。" % (state, why or ""))


def post(url, path, body, timeout):
    req = urllib.request.Request(url + path, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, OSError) as e:
        return None, {"error": str(e)}


def check_server(url, full):
    try:
        with urllib.request.urlopen(url + "/health", timeout=5) as r:
            row("OK", "サーバー疎通 /health", json.loads(r.read().decode("utf-8")).get("status", ""))
    except (urllib.error.URLError, OSError) as e:
        row("NG", "サーバー疎通 /health", "%s に繋がりません(%s)。local_scan_server.py を起動してください。" % (url, e))
        return
    cases = [("netcheck", "/scan/netcheck", {"targets": "127.0.0.1", "ports": "standard"}, 120),
             ("HTTPバナー取得(軽量)", "/scan/httplite", {"targets": "127.0.0.1", "i_own_these": True}, 60),
             ("追加プロトコル(軽量, tls:443)", "/scan/multiproto",
              {"targets": "127.0.0.1", "i_own_these": True, "module": "tls"}, 60)]
    if full:
        cases += [("gitleaks", "/scan/gitleaks", {}, 600), ("Trivy", "/scan/trivy", {}, 600),
                  ("Semgrep", "/scan/semgrep", {}, 900)]
    for name, path, body, timeout in cases:
        code, j = post(url, path, body, timeout)
        if code == 200:
            n = len(j) if isinstance(j, list) else len(j.get("results", [])) if isinstance(j, dict) else 0
            row("OK", name, "応答あり(%d件)" % n)
        elif code is None:
            row("NG", name, "通信エラー: %s" % j.get("error", ""))
        elif code == 500:
            row("NG", name, "サーバー内部エラー: %s" % j.get("error", ""))
        else:
            row("警告", name, "HTTP %s: %s" % (code, str(j.get("error", ""))[:200]))


def main():
    ap = argparse.ArgumentParser(description="ローカルスキャナー(local_scan_server.py)の自己診断")
    ap.add_argument("--url", default="http://127.0.0.1:8766", help="local_scan_server.pyのURL")
    ap.add_argument("--full", action="store_true", help="Semgrep/Trivy/gitleaksも実行する(数分かかる)")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    port = int(a.url.rsplit(":", 1)[-1].split("/")[0]) if a.url.count(":") >= 2 else 8766
    check_environment()
    check_ports(port)
    check_server(a.url.rstrip("/"), a.full)
    width = max(len(r[1]) for r in ROWS)
    lines = ["[%s] %s  %s" % (s.ljust(2), item.ljust(width), detail) for s, item, detail in ROWS]
    ng = sum(1 for r in ROWS if r[0] == "NG")
    warn = sum(1 for r in ROWS if r[0] == "警告")
    lines.append("")
    lines.append("結果: NG %d件 / 警告 %d件" % (ng, warn))
    text = "\n".join(lines)
    print(text)
    out_dir = os.path.join(REPO_ROOT, "results", "local-scan")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "selfcheck.txt")
    with open(out, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print("保存先: %s" % out)
    return 1 if ng else 0


if __name__ == "__main__":
    sys.exit(main())
