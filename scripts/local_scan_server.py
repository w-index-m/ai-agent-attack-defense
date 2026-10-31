#!/usr/bin/env python3
"""local_scan_server: vuln_triage.html から、このリポジトリ自身を対象に、既存の診断ツール
(Semgrep・Trivy・gitleaks・netcheck・zgrab2)を実際に呼び出すための、ローカル専用の補助サーバー。

設計方針（確認専用。このリポジトリの方針そのまま）:
  - 127.0.0.1 だけで待ち受ける。外部からは届かない。
  - 対象は**このリポジトリ自身の作業ツリー**に固定。リクエストでパスを指定することはできない
    （このスクリプトの場所からリポジトリルートを自分で解決する。外部入力は一切信用しない）。
  - Semgrep・Trivy・gitleaks は、.github/workflows/security-scan.yml の CI ステップと同じ
    コマンドをそのまま実行し、各ツールの生の JSON をそのまま返す（加工しない）。
  - netcheck は、netcheck/netcheck.py の設定・許可範囲判定をそのまま再利用する（ここで範囲を
    広げることはできない）。
  - zgrab2 は能動スキャナのため、scripts/zgrab2_guard.py と同じ同意フラグ（i_own_these）が
    無いと一切実行しない。対象は、リクエストで明示したものだけ（既定値を勝手に広げない）。
  - CORS は localhost 系オリジンにだけ許可する（ブラウザの file:// / http://localhost から
    直接 fetch するため）。これはローカル開発用のツールであり、localhost の外には絶対に
    公開しないこと。

vuln_triage.html の「5. 自前LLMに質問する」が http://localhost:11434 を直接 fetch するのと
同じパターン。詳細: security-scan/local-scan-server-notes.md

使い方:
    python3 scripts/local_scan_server.py [--port 8766]
"""
import argparse
import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
RESULTS_DIR = os.path.join(REPO_ROOT, "results", "local-scan")
TIMEOUT_SEC = 300

# localhost 系オリジンだけを許可する（file:// から開いた場合、Origin ヘッダは "null" になる）。
ALLOWED_ORIGIN_PREFIXES = ("http://localhost", "http://127.0.0.1", "null")


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _which(name):
    return shutil.which(name)


def _docker_available():
    if _which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def _run(cmd, cwd=None, timeout=TIMEOUT_SEC):
    """コマンドを実行し、(returncode, stdout_bytes, stderr_text) を返す。例外は出さない。"""
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace")
    except FileNotFoundError as e:
        return None, b"", str(e)
    except subprocess.TimeoutExpired:
        return None, b"", "タイムアウトしました(%d秒)" % timeout


def scan_semgrep():
    """CI(.github/workflows/security-scan.yml)の Semgrep ステップと同じコマンド。
    ローカルに semgrep があればそれを使い、無ければ docker にフォールバックする。"""
    out_path = os.path.join(RESULTS_DIR, "semgrep.json")
    exclude = "security-scan/sqli-lab/vulnerable_app.py"
    if _which("semgrep"):
        cmd = ["semgrep", "scan", "--config", "p/default", "--exclude", exclude,
               "--json", "--output", out_path, "--metrics=off"]
        rc, _out, err = _run(cmd, cwd=REPO_ROOT)
    elif _docker_available():
        cmd = ["docker", "run", "--rm", "-v", "%s:/src" % REPO_ROOT, "-w", "/src",
               "semgrep/semgrep:latest", "semgrep", "scan", "--config", "p/default",
               "--exclude", exclude, "--json", "--output", "/src/results/local-scan/semgrep.json",
               "--metrics=off"]
        rc, _out, err = _run(cmd)
    else:
        return {"error": "semgrepコマンドもDockerも見つかりません。semgrepをインストールするか、"
                          "Docker Desktopを起動してください。"}
    if not os.path.exists(out_path):
        return {"error": "Semgrepの結果ファイルができませんでした(診断が実行されていません)。",
                "returncode": rc, "stderr": err[-2000:]}
    with open(out_path, encoding="utf-8") as f:
        return json.load(f)


def scan_trivy():
    """CI の Trivy ステップと同じコマンド。ローカルに trivy があればそれを使う。"""
    out_path = os.path.join(RESULTS_DIR, "trivy.json")
    if _which("trivy"):
        cmd = ["trivy", "fs", "--scanners", "vuln,misconfig,secret", "--format", "json",
               "--output", out_path, "."]
        rc, _out, err = _run(cmd, cwd=REPO_ROOT)
    elif _docker_available():
        cmd = ["docker", "run", "--rm", "-v", "%s:/work" % REPO_ROOT, "-w", "/work",
               "aquasec/trivy:latest", "fs", "--scanners", "vuln,misconfig,secret",
               "--format", "json", "--output", "/work/results/local-scan/trivy.json", "."]
        rc, _out, err = _run(cmd)
    else:
        return {"error": "trivyコマンドもDockerも見つかりません。Docker Desktopを起動してください。"}
    if not os.path.exists(out_path):
        return {"error": "Trivyの結果ファイルができませんでした。", "returncode": rc,
                "stderr": err[-2000:]}
    with open(out_path, encoding="utf-8") as f:
        return json.load(f)


def scan_gitleaks():
    """CI の gitleaks ステップと同じコマンド。"""
    out_path = os.path.join(RESULTS_DIR, "gitleaks.json")
    if _which("gitleaks"):
        cmd = ["gitleaks", "detect", "--source", REPO_ROOT, "--report-format", "json",
               "--report-path", out_path, "--exit-code", "0", "--no-banner"]
        rc, _out, err = _run(cmd)
    elif _docker_available():
        cmd = ["docker", "run", "--rm", "-v", "%s:/repo" % REPO_ROOT,
               "zricethezav/gitleaks:latest", "detect", "--source=/repo",
               "--report-format=json", "--report-path=/repo/results/local-scan/gitleaks.json",
               "--exit-code=0", "--no-banner"]
        rc, _out, err = _run(cmd)
    else:
        return {"error": "gitleaksコマンドもDockerも見つかりません。Docker Desktopを起動してください。"}
    if not os.path.exists(out_path):
        # gitleaks は、検出が0件だと報告ファイル自体を作らないことがある。その場合は空配列を返す。
        return []
    with open(out_path, encoding="utf-8") as f:
        text = f.read().strip()
        return json.loads(text) if text else []


def scan_netcheck(body):
    """netcheck/netcheck.py 自身の設定・許可範囲判定をそのまま使う(ここで範囲は広げない)。
    サーバーを別途立てず、ジョブを同期的に実行して結果だけ返す。"""
    nc = _load_module(os.path.join(REPO_ROOT, "netcheck", "netcheck.py"), "netcheck_local")
    cfg = nc.load_config()
    targets_text = str((body or {}).get("targets", "") or "127.0.0.1")
    try:
        targets, refused = nc.expand_targets(targets_text, cfg)
    except nc.TooMany as e:
        return {"error": str(e)}
    if refused:
        return {"error": "許可した範囲の外、または解釈できない対象があります。実行しません。",
                "refused": refused,
                "allowed": [str(n) for n in nc.allowed_networks(cfg)]}
    if not targets:
        return {"error": "対象がありません。"}
    ports = nc.EXTENDED_PORTS if (body or {}).get("ports") == "extended" else nc.STANDARD_PORTS
    admin = bool((body or {}).get("admin", True))
    results = []
    deadline = time.monotonic() + TIMEOUT_SEC
    truncated = False
    for name, ip in targets:
        if time.monotonic() >= deadline:
            # 対象が多すぎて(ポート数×対象数)、このHTTPリクエスト1回の枠内で終わらない場合は
            # ここで打ち切り、取れた分だけ返す(無期限にサーバーを占有しない)。範囲を絞って
            # 再実行するか、対象を1台ずつ指定することを勧める。
            truncated = True
            break
        results.append(nc.check_host(name, ip, ports, cfg, admin, lambda: None))
    out = {"id": "local-scan", "status": "done", "sqli_note": getattr(nc, "SQLI_NOTE", ""),
           "results": results}
    if truncated:
        out["truncated"] = True
        out["truncated_note"] = ("対象が多すぎて制限時間(%d秒)内に終わらなかったため、%d/%d台で打ち切りました。"
                                  "範囲を絞るか、対象を1台ずつ指定してください。"
                                  % (TIMEOUT_SEC, len(results), len(targets)))
    return out


def scan_zgrab2(body):
    """能動スキャナ。scripts/zgrab2_guard.py と同じ同意フラグが無いと一切実行しない。
    zgrab2 本体が入っていない場合は、その旨を明確なエラーで返す(黙ってスキップしない)。"""
    body = body or {}
    if body.get("i_own_these") is not True:
        return {"error": "拒否: i_own_these(自社が管理している、または書面で許可を得た対象であること)が"
                          "trueである必要があります。"}
    targets_text = str(body.get("targets", "") or "")
    if not targets_text.strip():
        return {"error": "対象を入力してください。"}
    guard = _load_module(os.path.join(HERE, "zgrab2_guard.py"), "zgrab2_guard_local")
    nc = _load_module(os.path.join(REPO_ROOT, "netcheck", "netcheck.py"), "netcheck_local_for_guard")
    cfg = nc.load_config()
    try:
        ok, refused = nc.expand_targets(targets_text, cfg)
    except nc.TooMany as e:
        return {"error": str(e)}
    if refused:
        return {"error": "許可した範囲の外、または解釈できない対象があります。何も実行しません。",
                "refused": refused}
    if not ok:
        return {"error": "対象がありません。"}
    lines = []
    seen = set()
    for name, ip in ok:
        line = ip if name == ip else "%s, %s" % (ip, name)
        if line not in seen:
            seen.add(line)
            lines.append(line)
    if _which("zgrab2") is None:
        return {"error": "zgrab2本体がこの機器にインストールされていません。"
                          "https://github.com/zmap/zgrab2 を参照してビルド・配置してください。"
                          "(許可範囲チェックは通過しました: %s)" % ", ".join(lines)}
    module = str(body.get("module", "http") or "http")
    cmd = ["zgrab2", module]
    try:
        p = subprocess.run(cmd, input=("\n".join(lines) + "\n").encode("utf-8"),
                            capture_output=True, timeout=TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        return {"error": "タイムアウトしました(%d秒)" % TIMEOUT_SEC}
    out_lines = [l for l in p.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
    results = []
    for l in out_lines:
        try:
            results.append(json.loads(l))
        except ValueError:
            pass
    return results


ROUTES = {
    "/scan/semgrep": lambda body: scan_semgrep(),
    "/scan/trivy": lambda body: scan_trivy(),
    "/scan/gitleaks": lambda body: scan_gitleaks(),
    "/scan/netcheck": lambda body: scan_netcheck(body),
    "/scan/zgrab2": lambda body: scan_zgrab2(body),
}

_LOCK = threading.Lock()  # 一度に1つのスキャンだけ(同じツールの結果ファイルを使い回すため)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "local-scan-server"

    def log_message(self, *a):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # ブラウザ側が先に接続を切った場合(タブの再読み込み・クローズ等)。
            # サーバー側の不具合ではないので、トレースバックは出さず黙って無視する。
            pass

    def _cors_origin(self):
        origin = self.headers.get("Origin", "")
        if origin.startswith(ALLOWED_ORIGIN_PREFIXES) or origin == "null":
            return origin
        return None

    def _send(self, code, body):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        origin = self._cors_origin()
        if origin is not None:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self._cors_origin()
        if origin is not None:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok", "repo_root": REPO_ROOT})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ROUTES:
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            return self._send(400, {"error": "JSONの形式が不正です。"})
        with _LOCK:
            try:
                result = ROUTES[self.path](body)
            except Exception as e:  # noqa
                return self._send(500, {"error": "内部エラー: %s" % e})
        code = 400 if isinstance(result, dict) and "error" in result else 200
        self._send(code, result)


def main():
    ap = argparse.ArgumentParser(description="vuln_triage.html から、このリポジトリ自身を対象に"
                                              "各診断ツールを実際に呼び出す、ローカル専用の補助サーバー")
    ap.add_argument("--port", type=int, default=8766, help="待ち受けポート(既定 8766)")
    a = ap.parse_args()
    os.makedirs(RESULTS_DIR, exist_ok=True)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print("local_scan_server: http://127.0.0.1:%d で待ち受け中(Ctrl+Cで終了)" % a.port)
    print("対象リポジトリ: %s" % REPO_ROOT)
    print("vuln_triage.html の「ローカルスキャナーを呼び出す」から利用してください。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
