#!/usr/bin/env python3
"""local_scan_server: vuln_triage.html から、このリポジトリ自身を対象に、既存の診断ツール
(Semgrep・Trivy・gitleaks・netcheck・zgrab2・Strix・Cairn)を実際に呼び出すための、
ローカル専用の補助サーバー。

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


def _resolve_single_target(body, default_host="127.0.0.1"):
    """能動攻撃系エンドポイント(Strix/Cairn)向けに、対象を1つだけ解決する。
    netcheck/zgrab2_guardと同じ許可範囲判定(netcheck/config.jsonのallowed_ranges)を
    必ず通す(ここで範囲は広げない)。戻り値は (ip, None) または (None, error_dict)。"""
    nc = _load_module(os.path.join(REPO_ROOT, "netcheck", "netcheck.py"), "netcheck_local_for_target")
    cfg = nc.load_config()
    targets_text = str((body or {}).get("targets", "") or default_host)
    try:
        targets, refused = nc.expand_targets(targets_text, cfg)
    except nc.TooMany as e:
        return None, {"error": str(e)}
    if refused:
        return None, {"error": "許可した範囲の外、または解釈できない対象があります。実行しません。",
                       "refused": refused,
                       "allowed": [str(n) for n in nc.allowed_networks(cfg)]}
    if not targets:
        return None, {"error": "対象がありません。"}
    if len(targets) > 1:
        return None, {"error": "対象は1台だけ指定してください(複数/範囲指定は不可)。"}
    return targets[0][1], None


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


STRIX_TIMEOUT_SEC = 900  # Strix自体の完走には数分かかりうるため、他のエンドポイントより長め


def _port_open(host, port, timeout=0.5):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()


def _ensure_background(cmd, cwd, env, host, port, wait_sec=20):
    """host:port が既に待ち受けていなければ、cmd をバックグラウンドで起動し、
    待ち受け開始まで待つ(最大 wait_sec 秒)。新規に起動したかどうかを返す。"""
    if _port_open(host, port):
        return False
    subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      stdin=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + wait_sec
    while time.monotonic() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.5)
    return True  # 起動は試みた。疎通未確認のまま次に進み、Strix側のエラーに委ねる。


def scan_strix(body):
    """Strix(usestrix/strix)のモックLLMベースPoCを、GUIから起動する。

    能動的にこのリポジトリ自身のsqli-labデモアプリへ攻撃ペイロードを送る(SQLi認証バイパス等)ため、
    zgrab2と同じ同意フラグ(i_own_these)が無いと一切実行しない。

    対象となるStrixの作業コピーは、このエンドポイント自身がcloneすることはしない(第三者コードの
    無断取得・パッチ適用を黙って行わないため)。環境変数 STRIX_LOCAL_DIR に、あらかじめ
    security-scan/strix-local-poc/README.md の手順(clone → パッチ適用 → uv sync)を済ませた
    Strixの作業コピーのパスを設定しておく必要がある。
    """
    body = body or {}
    if body.get("i_own_these") is not True:
        return {"error": "拒否: i_own_these(自社が管理している、または書面で許可を得た対象への"
                          "攻撃実行に同意すること)がtrueである必要があります。"}

    target_ip, err = _resolve_single_target(body)
    if err:
        return err
    target = "%s:5000" % target_ip

    strix_dir = os.environ.get("STRIX_LOCAL_DIR", "").strip()
    if not strix_dir or not os.path.isdir(strix_dir):
        return {"error": "STRIX_LOCAL_DIRが設定されていないか、ディレクトリが存在しません。"
                          "事前にsecurity-scan/strix-local-poc/README.mdの手順("
                          "git clone https://github.com/usestrix/strix → "
                          "strix-local-backend.patch等を適用 → uv sync)を済ませ、"
                          "local_scan_server.pyを起動する前に "
                          "STRIX_LOCAL_DIR=/path/to/strix を環境変数で指定してください。"}
    if _which("uv") is None:
        return {"error": "uvコマンドが見つかりません。https://docs.astral.sh/uv/ を参照してインストールしてください。"}

    vuln_app = os.path.join(REPO_ROOT, "security-scan", "sqli-lab", "vulnerable_app.py")
    mock_llm = os.path.join(REPO_ROOT, "security-scan", "strix-local-poc", "mock_llm_server.py")
    if not os.path.exists(vuln_app) or not os.path.exists(mock_llm):
        return {"error": "sqli-labのvulnerable_app.py、またはstrix-local-pocのmock_llm_server.pyが"
                          "見つかりません(リポジトリの構成が想定と違います)。"}

    if target_ip == "127.0.0.1":
        # 既定(このリポジトリ自身のsqli-labデモアプリ)の場合だけ、ローカルで自動起動する。
        vuln_env = dict(os.environ)
        vuln_env.setdefault("VULN_APP_HOST", "127.0.0.1")
        _ensure_background([sys.executable, vuln_app], REPO_ROOT, vuln_env, "127.0.0.1", 5000)
    elif not _port_open(target_ip, 5000):
        return {"error": "対象(%s:5000)に接続できません。許可範囲内の別端末を指定した場合は、"
                          "そちら側で対象アプリ(sqli-labのvulnerable_app.pyと同じ"
                          "/loginエンドポイント相当)を先に起動しておいてください。" % target_ip}
    _ensure_background([sys.executable, mock_llm, "8899", target], REPO_ROOT, dict(os.environ),
                        "127.0.0.1", 8899)

    if not _port_open(target_ip, 5000) or not _port_open("127.0.0.1", 8899):
        return {"error": "対象(%s:5000)または mock_llm_server.py の起動を確認できませんでした。"
                          "手動で起動してから再試行してください(詳細: " % target_ip +
                          "security-scan/strix-local-poc/README.md)。"}

    strix_env = dict(os.environ)
    strix_env["STRIX_RUNTIME_BACKEND"] = "local"
    strix_env["STRIX_LLM"] = "openai/mock-model"
    strix_env["OPENAI_API_BASE"] = "http://127.0.0.1:8899/v1"
    strix_env["OPENAI_API_KEY"] = "dummy-mock-key"

    before_runs = set()
    runs_dir = os.path.join(strix_dir, "strix_runs")
    if os.path.isdir(runs_dir):
        before_runs = set(os.listdir(runs_dir))

    cmd = ["uv", "run", "strix", "-n", "-t", "./", "--scan-mode", "quick", "--max-budget", "10"]
    try:
        p = subprocess.run(cmd, cwd=strix_dir, env=strix_env, capture_output=True,
                            timeout=STRIX_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        return {"error": "Strixの実行がタイムアウトしました(%d秒)。" % STRIX_TIMEOUT_SEC}
    except FileNotFoundError as e:
        return {"error": "Strixの実行に失敗しました: %s" % e}

    if not os.path.isdir(runs_dir):
        return {"error": "strix_runsディレクトリが作成されませんでした(Strixが完走しなかった可能性があります)。",
                "returncode": p.returncode, "stderr": p.stderr.decode("utf-8", "replace")[-2000:]}
    after_runs = set(os.listdir(runs_dir))
    new_runs = sorted(after_runs - before_runs) or sorted(after_runs)
    if not new_runs:
        return {"error": "Strixの実行結果(strix_runs配下)が見つかりませんでした。",
                "returncode": p.returncode, "stderr": p.stderr.decode("utf-8", "replace")[-2000:]}
    run_id = new_runs[-1]
    sarif_path = os.path.join(runs_dir, run_id, "findings.sarif")
    if not os.path.exists(sarif_path):
        return {"error": "findings.sarifが見つかりませんでした(run_id=%s)。"
                          "脆弱性が検出されなかった可能性があります。" % run_id,
                "returncode": p.returncode}
    with open(sarif_path, encoding="utf-8") as f:
        return json.load(f)


CAIRN_SERVE_PORT = 8010  # このエンドポイント専用。他で手動起動したcairn serveと衝突しないよう固定ポート
CAIRN_TIMEOUT_SEC = 120  # LLMもDockerも使わない単発シナリオなので、Strixより短い既定値で十分


def scan_cairn(body):
    """Cairn(oritera/Cairn)を、GUIから起動する。

    能動的にこのリポジトリ自身のsqli-labデモアプリへ攻撃ペイロードを送る(SQLi認証バイパス)ため、
    zgrab2/Strixと同じ同意フラグ(i_own_these)が無いと一切実行しない。

    Cairnの実ディスパッチャ(cairn dispatch、Docker workerコンテナ+LLM)は、workerの応答が
    Cairn独自のJSONスキーマに従うことを要求しており、台本によるプレーンテキスト応答では
    「JSON解析失敗」としてタスクが完了せず無限リトライになることが既に分かっている
    (cairn-authorized-lab-runbook.md §6.5)。このため、このエンドポイントはdispatch/worker/LLMを
    一切使わず、Cairn自身のサーバーAPI(CairnClient)を、PR #89のhandoff_recheck_test.pyと同じ
    手法で直接呼び出す(security-scan/cairn-lab/run_real_scan.py)。実際にcurlでSQLi認証バイパスを
    再現し、その結果をCairnのFactとして記録する。

    対象となるCairnの作業コピーは、このエンドポイント自身がcloneすることはしない。環境変数
    CAIRN_LOCAL_DIR に、あらかじめ security-scan/cairn-lab/cairn-authorized-lab-runbook.md の
    手順(git clone https://github.com/oritera/Cairn → uv sync --project cairn)を済ませた
    Cairnの作業コピーのパスを設定しておく必要がある。
    """
    body = body or {}
    if body.get("i_own_these") is not True:
        return {"error": "拒否: i_own_these(自社が管理している、または書面で許可を得た対象への"
                          "攻撃実行に同意すること)がtrueである必要があります。"}

    target_ip, err = _resolve_single_target(body)
    if err:
        return err

    cairn_dir = os.environ.get("CAIRN_LOCAL_DIR", "").strip()
    if not cairn_dir or not os.path.isdir(cairn_dir):
        return {"error": "CAIRN_LOCAL_DIRが設定されていないか、ディレクトリが存在しません。"
                          "事前にsecurity-scan/cairn-lab/cairn-authorized-lab-runbook.mdの手順("
                          "git clone https://github.com/oritera/Cairn → uv sync --project cairn)を"
                          "済ませ、local_scan_server.pyを起動する前に "
                          "CAIRN_LOCAL_DIR=/path/to/Cairn を環境変数で指定してください。"}
    if _which("uv") is None:
        return {"error": "uvコマンドが見つかりません。https://docs.astral.sh/uv/ を参照してインストールしてください。"}

    cairn_src = os.path.join(cairn_dir, "cairn", "src")
    if not os.path.isdir(cairn_src):
        return {"error": "CAIRN_LOCAL_DIR配下にcairn/srcが見つかりません"
                          "(CAIRN_LOCAL_DIRは、Cairnリポジトリのルート(cairn/サブディレクトリを"
                          "含む)を指定してください)。"}

    vuln_app = os.path.join(REPO_ROOT, "security-scan", "sqli-lab", "vulnerable_app.py")
    run_script = os.path.join(HERE, "..", "security-scan", "cairn-lab", "run_real_scan.py")
    if not os.path.exists(vuln_app) or not os.path.exists(run_script):
        return {"error": "sqli-labのvulnerable_app.py、またはcairn-lab/run_real_scan.pyが"
                          "見つかりません(リポジトリの構成が想定と違います)。"}

    if target_ip == "127.0.0.1":
        # 既定(このリポジトリ自身のsqli-labデモアプリ)の場合だけ、ローカルで自動起動する。
        vuln_env = dict(os.environ)
        vuln_env.setdefault("VULN_APP_HOST", "127.0.0.1")
        _ensure_background([sys.executable, vuln_app], REPO_ROOT, vuln_env, "127.0.0.1", 5000)
    elif not _port_open(target_ip, 5000):
        return {"error": "対象(%s:5000)に接続できません。許可範囲内の別端末を指定した場合は、"
                          "そちら側で対象アプリ(sqli-labのvulnerable_app.pyと同じ"
                          "/loginエンドポイント相当)を先に起動しておいてください。" % target_ip}

    cairn_env = dict(os.environ)
    cairn_env.setdefault("UV_DEFAULT_INDEX", "https://pypi.org/simple")
    _ensure_background(
        ["uv", "run", "--project", "cairn", "cairn", "serve", "--host", "127.0.0.1",
         "--port", str(CAIRN_SERVE_PORT)],
        cairn_dir, cairn_env, "127.0.0.1", CAIRN_SERVE_PORT, wait_sec=30)

    if not _port_open(target_ip, 5000) or not _port_open("127.0.0.1", CAIRN_SERVE_PORT):
        return {"error": "対象(%s:5000)または cairn serve の起動を確認できませんでした。"
                          "手動で起動してから再試行してください(詳細: " % target_ip +
                          "security-scan/cairn-lab/cairn-authorized-lab-runbook.md)。"}

    cmd = [sys.executable, run_script, "--cairn-src", cairn_src,
           "--base-url", "http://127.0.0.1:%d" % CAIRN_SERVE_PORT,
           "--target", "http://%s:5000" % target_ip]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=CAIRN_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        return {"error": "Cairnの実行がタイムアウトしました(%d秒)。" % CAIRN_TIMEOUT_SEC}
    if p.returncode != 0:
        return {"error": "Cairnの実行に失敗しました。",
                "returncode": p.returncode, "stderr": p.stderr.decode("utf-8", "replace")[-2000:]}

    try:
        import yaml
    except ImportError:
        return {"error": "PyYAMLが見つかりません(Cairnの出力(YAML)を読むために必要です)。"
                          "pip install pyyaml を実行してください。"}
    try:
        parsed = yaml.safe_load(p.stdout.decode("utf-8", "replace"))
    except Exception as e:
        return {"error": "Cairnの出力(YAML)の解析に失敗しました: %s" % e}

    target_uri = ("security-scan/sqli-lab/vulnerable_app.py" if target_ip == "127.0.0.1"
                  else "http://%s:5000/login" % target_ip)
    facts = (parsed or {}).get("facts") or []
    results = []
    for fact in facts:
        fid = fact.get("id", "")
        if fid in ("origin", "goal"):
            continue  # origin/goalは入力そのものであり、発見(Fact)ではない
        results.append({
            "ruleId": "cairn-finding",
            "level": "warning",
            "message": {"text": fact.get("description", "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": target_uri}}}],
            "properties": {"title": "Cairn: " + fid},
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "Cairn"}}, "results": results}],
    }


def scan_httplite(body):
    """zgrab2本体が無くても使える、HTTP/HTTPSバナー取得だけの軽量な代替(scripts/http_lite_banner.py)。
    zgrab2と同じ同意フラグ(i_own_these)・許可範囲判定が無いと一切実行しない。出力はzgrab2のhttp
    モジュールと互換の形式で返すため、GUI側の取り込みロジック(zgrab2として自動判別)をそのまま
    再利用できる。"""
    body = body or {}
    if body.get("i_own_these") is not True:
        return {"error": "拒否: i_own_these(自社が管理している、または書面で許可を得た対象であること)が"
                          "trueである必要があります。"}
    targets_text = str(body.get("targets", "") or "")
    if not targets_text.strip():
        return {"error": "対象を入力してください。"}
    nc = _load_module(os.path.join(REPO_ROOT, "netcheck", "netcheck.py"), "netcheck_local_for_httplite")
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
    hlb = _load_module(os.path.join(HERE, "http_lite_banner.py"), "http_lite_banner_local")
    rows = []
    for name, ip in ok:
        host = name if name != ip else None
        rows.extend(hlb.grab_target(ip, host=host, timeout=5.0))
    return rows


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
    "/scan/httplite": lambda body: scan_httplite(body),
    "/scan/strix": lambda body: scan_strix(body),
    "/scan/cairn": lambda body: scan_cairn(body),
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
