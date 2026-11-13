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
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
RESULTS_DIR = os.path.join(REPO_ROOT, "results", "local-scan")
TIMEOUT_SEC = 300
# local_scan_selfcheck.py --url の既定値と合わせるための、このサーバー自身の待ち受けポート。
# main()が--portを解釈した時点で上書きする(既定 8766)。
SERVER_PORT = 8766
# sqli-labデモアプリ(vulnerable_app.py)の既定ポート。環境変数VULN_APP_PORTで変更できる
# (例: Windowsでウイルス対策ソフト等が5000/5001番を常時専有している場合の回避策)。
# vulnerable_app.py自身も同じ環境変数を見るので、起動時に渡す環境にも含めておけば一致する。
VULN_APP_PORT = int(os.environ.get("VULN_APP_PORT", "5000"))

# localhost 系オリジンだけを許可する（file:// から開いた場合、Origin ヘッダは "null" になる）。
ALLOWED_ORIGIN_PREFIXES = ("http://localhost", "http://127.0.0.1", "null")


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _which(name):
    return shutil.which(name)


_ZGRAB2_BUILD_DIR = os.path.join(os.path.expanduser("~"), ".cache", "local_scan_server", "bin")
_ZGRAB2_BUILD_ATTEMPTED = False
_ZGRAB2_BUILD_TIMEOUT_SEC = 300


def _ensure_zgrab2():
    """zgrab2本体のパスを返す(見つからなければNone)。PATH上に無ければ、過去にこの
    サーバーが自前でビルドした分(_ZGRAB2_BUILD_DIR)を探す。それも無く、かつこのサーバー
    プロセスでまだ試していなければ、Go(https://github.com/zmap/zgrab2、本家ソース)から
    `go install`で1回だけビルドを試みる(goが無い/ビルド失敗の場合は以後このプロセスでは
    再試行しない。再度試したい場合はサーバーを再起動する)。
    zgrab2はデフォルトで~/.config/zgrab2/blocklist.confを要求し、無いと起動時に
    fatalで落ちるため、空ファイルが無ければ作っておく(スキャン対象を狭めるものではなく、
    単に『除外リストが空』という設定を明示するだけ)。"""
    global _ZGRAB2_BUILD_ATTEMPTED
    found = _which("zgrab2")
    if found is None:
        cached = os.path.join(_ZGRAB2_BUILD_DIR, "zgrab2")
        if os.path.exists(cached):
            found = cached
    if found is None and not _ZGRAB2_BUILD_ATTEMPTED:
        _ZGRAB2_BUILD_ATTEMPTED = True
        go = _which("go")
        if go is not None:
            os.makedirs(_ZGRAB2_BUILD_DIR, exist_ok=True)
            env = dict(os.environ)
            env["GOBIN"] = _ZGRAB2_BUILD_DIR
            env.setdefault("GOPROXY", "https://proxy.golang.org,direct")
            try:
                subprocess.run([go, "install", "github.com/zmap/zgrab2/cmd/zgrab2@latest"],
                                env=env, capture_output=True, timeout=_ZGRAB2_BUILD_TIMEOUT_SEC)
            except subprocess.TimeoutExpired:
                pass
            cached = os.path.join(_ZGRAB2_BUILD_DIR, "zgrab2")
            if os.path.exists(cached):
                found = cached
    if found is not None:
        blocklist_dir = os.path.join(os.path.expanduser("~"), ".config", "zgrab2")
        blocklist_path = os.path.join(blocklist_dir, "blocklist.conf")
        if not os.path.exists(blocklist_path):
            os.makedirs(blocklist_dir, exist_ok=True)
            with open(blocklist_path, "w", encoding="utf-8"):
                pass
    return found


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


_DEP_MANIFEST_RE = re.compile(
    r"(^|/)(requirements[^/]*\.txt|package-lock\.json|packages\.lock\.json|poetry\.lock|uv\.lock|go\.sum|pom\.xml)$"
    r"|\.csproj$"
)


def scan_dep_cve():
    """CI(security-scan.yml)の「依存関係の既知の脆弱性(OSV)」ステップと同じ、ファイルの
    自動探索+照合をそのまま再利用する。読み取り専用(OSV.devへの問い合わせのみ)。対象は
    このリポジトリ自身の依存関係ファイルに固定(リクエストでパスは指定できない)。"""
    out_path = os.path.join(RESULTS_DIR, "dep_cve.json")
    rc, out, err = _run(["git", "ls-files"], cwd=REPO_ROOT)
    if rc != 0:
        return {"error": "git ls-files に失敗しました: %s" % err}
    args = []
    for f in out.decode("utf-8", "replace").splitlines():
        if not _DEP_MANIFEST_RE.search(f):
            continue
        if f.endswith("package-lock.json"):
            args += ["--npm-lock", f]
        elif f.endswith("packages.lock.json"):
            args += ["--nuget-lock", f]
        elif f.endswith(".csproj"):
            args += ["--csproj", f]
        elif f.endswith("poetry.lock"):
            args += ["--poetry-lock", f]
        elif f.endswith("uv.lock"):
            args += ["--uv-lock", f]
        elif f.endswith("go.sum"):
            args += ["--go-sum", f]
        elif f.endswith("pom.xml"):
            args += ["--pom", f]
        else:
            args += ["--requirements", f]
    if not args:
        # CIの「依存関係の照合: 対象のファイルがありません(スキップ)」と同じ扱い。このリポジトリ
        # 自身は標準ライブラリのみで動くため、通常はここに該当する(エラーではない)。
        return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "dep_cve_check", "rules": []}},
                "results": []}], "_skip_reason": "対象ファイル(requirements*.txt・pom.xml等)が見つかりません。"}
    cmd = [sys.executable, os.path.join(HERE, "dep_cve_check.py")] + args + ["--out", out_path]
    rc, _out, err = _run(cmd, cwd=REPO_ROOT)
    if not os.path.exists(out_path):
        return {"error": "dep_cve_check の結果ファイルができませんでした。", "returncode": rc,
                "stderr": err[-2000:]}
    with open(out_path, encoding="utf-8") as f:
        return json.load(f)


def _run_version_check_script(script_name, extra_args=None):
    """node_version_check.py等の「確認だけ・--outでSARIFを書き出す」版スクリプトに共通の
    呼び出し方。このホスト(local_scan_server.pyを起動したPC自身)に対して実行する。
    スクリプト自身がコマンド不在等を検知済み/未検出として扱うため、ここでは常に結果SARIFを
    返す(「見つからなかった」ことも、確認結果の1つとして扱う。他のボタンと同じ設計)。"""
    out_path = os.path.join(RESULTS_DIR, "%s.sarif" % script_name)
    cmd = [sys.executable, "-I", os.path.join(HERE, "%s.py" % script_name), "--out", out_path]
    cmd += extra_args or []
    rc, _out, err = _run(cmd, cwd=REPO_ROOT)
    if not os.path.exists(out_path):
        return {"error": "%s の結果ファイルができませんでした。" % script_name, "returncode": rc,
                "stderr": err[-2000:]}
    with open(out_path, encoding="utf-8") as f:
        sarif = json.load(f)
    _fill_missing_sarif_titles(sarif)
    return sarif


_MAX_AUTO_TITLE_LEN = 80


def _fill_missing_sarif_titles(sarif):
    """vuln_triage.html側は、一覧の太字見出しにproperties.titleを使う(無いと
    「ruleId: ruleId」という意味の無い見出しになる)。node_version_check.py等、
    このリポジトリの検知スクリプトの大半は、もともとCLI出力用のSARIFしか作っておらず
    properties.titleを持たない。ここで、持っていない結果だけに、message.textの先頭
    (短く切った1行)をtitleとして補う(各スクリプト自身は変更しない、UI統合側だけの
    後処理)。"""
    for run in (sarif.get("runs") or []):
        for r in (run.get("results") or []):
            props = r.setdefault("properties", {})
            if props.get("title"):
                continue
            text = ((r.get("message") or {}).get("text") or "").strip()
            first_line = text.splitlines()[0] if text else ""
            if len(first_line) > _MAX_AUTO_TITLE_LEN:
                first_line = first_line[:_MAX_AUTO_TITLE_LEN] + "..."
            props["title"] = first_line or r.get("ruleId", "")


def scan_os_patch():
    """このホスト自身のOS更新状態を確認する。OSごとに別スクリプト
    (os_patch_check_linux.py / os_patch_check_windows.py)があるため、
    platform.system()でこのサーバーが動いているOSを判定し、該当する方を実行する
    (利用者がボタンを押すだけで、OSを意識せず使えるようにするため)。"""
    system = platform.system()
    if system == "Windows":
        return _run_version_check_script("os_patch_check_windows")
    if system == "Linux":
        return _run_version_check_script("os_patch_check_linux")
    return {"error": "os_patch_check は Linux(RHEL系)とWindowsのみ対応です(検出したOS: %s)。" % system}


def scan_node_version():
    return _run_version_check_script("node_version_check")


def scan_python_brotli():
    return _run_version_check_script("python_brotli_check")


def scan_php_version():
    return _run_version_check_script("php_version_check")


def scan_bind_version():
    return _run_version_check_script("bind_version_check")


def scan_f5_bigip_apm():
    return _run_version_check_script("f5_bigip_apm_check")


def scan_java_cacerts_emudhra():
    return _run_version_check_script("java_cacerts_emudhra_check")


def scan_linux_kernel_cve202698432():
    return _run_version_check_script("linux_kernel_cve202698432_check")


def scan_linux_kernel_infinitycore():
    return _run_version_check_script("linux_kernel_infinitycore_check")


_SQLI_LAB_SEVERITY_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def scan_sqli_lab_regression():
    """sqli-lab自身の回帰テスト(run_regression.py)を実行する。対象は、このリポジトリの
    意図的に脆弱なデモアプリ(sqli-lab/vulnerable_app.py)で、vulnerable_app.py自身を
    ローカルに自動起動してから検証し、終了後に止める(run_regression.py自身の設計)。
    『このリポジトリの脆弱性』ではなく『ラボ自身の検出スクリプトが壊れていないか』の確認
    (詳細: sqli-lab/README.ja.mdのTODOセクション)。出力はrun_regression.py独自の
    JSON配列(sqli_lab.json形式)のため、他のボタンと同じSARIF形式に変換してから返す。"""
    out_path = os.path.join(RESULTS_DIR, "sqli_lab_regression.json")
    lab_dir = os.path.join(REPO_ROOT, "security-scan", "sqli-lab")
    cmd = [sys.executable, os.path.join(lab_dir, "run_regression.py"), "--out", out_path]
    rc, _out, err = _run(cmd, cwd=lab_dir, timeout=120)
    if not os.path.exists(out_path):
        return {"error": "sqli-lab/run_regression.py の結果ファイルができませんでした。",
                "returncode": rc, "stderr": err[-2000:]}
    with open(out_path, encoding="utf-8") as f:
        findings = json.load(f)
    results = []
    for item in findings:
        sev = str(item.get("severity", "high")).lower()
        results.append({
            "ruleId": "sqli_lab_regression",
            "level": _SQLI_LAB_SEVERITY_TO_LEVEL.get(sev, "warning"),
            "message": {"text": item.get("detail", "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(item.get("location", ""))}}}],
            # properties.titleは、vuln_triage.html側が一覧の太字見出しに使う短い表示名
            # (無いと「ruleId: ruleId」という意味の無い見出しになってしまう)。
            # run_regression.py自身が付けた、どのクラスのどのパスが誤判定されたかという
            # 説明(例: "regression: sqli scanner misclassified /login")をそのまま使う。
            "properties": {"severityLabel": sev, "title": item.get("title", "")},
        })
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "sqli_lab_regression",
                                "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "results": results,
        }],
        "_skip_reason": ("" if findings else
                          "sqli-labの全クラスが正しく分類されました(回帰なし)。これは"
                          "『このリポジトリの脆弱性が無い』ではなく、『ラボ自身の検出スクリプトが"
                          "壊れていない』ことの確認です。"),
    }


def scan_detection_regression():
    """scripts/run_detection_regression.pyを実行する。R1-R32系・CVEバージョン照合系の
    検知スクリプト自身(このリポジトリのコードそのもの)が、同梱の合成ログ(陽性/陰性)に対して
    壊れていないかの回帰テスト(CIのscanジョブと同じもの)。出力(detection_regression.json
    と同じJSON配列形式)をSARIF形式に変換してから返す。"""
    out_path = os.path.join(RESULTS_DIR, "detection_regression.json")
    cmd = [sys.executable, "-I", os.path.join(HERE, "run_detection_regression.py"), "--out", out_path]
    rc, _out, err = _run(cmd, cwd=REPO_ROOT, timeout=120)
    if not os.path.exists(out_path):
        return {"error": "scripts/run_detection_regression.py の結果ファイルができませんでした。",
                "returncode": rc, "stderr": err[-2000:]}
    with open(out_path, encoding="utf-8") as f:
        findings = json.load(f)
    results = []
    for item in findings:
        sev = str(item.get("severity", "high")).lower()
        results.append({
            "ruleId": "detection_regression",
            "level": _SQLI_LAB_SEVERITY_TO_LEVEL.get(sev, "warning"),
            "message": {"text": item.get("detail", "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(item.get("location", ""))}}}],
            # properties.title: 上のscan_sqli_lab_regression()と同じ理由。
            "properties": {"severityLabel": sev, "title": item.get("title", "")},
        })
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "detection_regression",
                                "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "results": results,
        }],
        "_skip_reason": ("" if findings else
                          "検知スクリプト18本が、合成ログの陽性/陰性入力をすべて正しく分類しました"
                          "(回帰なし)。"),
    }


def scan_local_selfcheck():
    """scripts/local_scan_selfcheck.pyを実行する。local_scan_server.py自身・対応する
    外部コマンド(Semgrep/Trivy/gitleaks等)の有無・ポートの状態を自己診断する。確認専用。"""
    cmd = [sys.executable, "-I", os.path.join(HERE, "local_scan_selfcheck.py"),
           "--url", "http://127.0.0.1:%d" % SERVER_PORT]
    rc, out, err = _run(cmd, cwd=REPO_ROOT, timeout=60)
    text = (out or b"").decode("utf-8", "replace")
    # local_scan_selfcheck.pyは--out未対応でJSONではなく読みやすいテキストの要約を標準出力に
    # 出す設計のため、そのまま1件のSARIF結果として返す(ボタンを押すだけで画面に出ることを優先)。
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "local_selfcheck",
                                "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "results": [{
                "ruleId": "local_selfcheck",
                "level": "note" if rc == 0 else "warning",
                "message": {"text": text[-3000:] or err[-3000:] or "(出力なし)"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "local_scan_selfcheck"}}}],
            }],
        }],
    }


# R1-R32系の「ログファイルを読むだけ」のスクリプト。script名 -> 追加のCLI引数(既定のままで
# 良いものが大半なので、ほぼ空リスト)。どれも標準で --log-path を受け取り、終了コード
# 0(ヒット無し)/1(ヒット有り)/2(読み取り失敗)を返す(--outでSARIFを書き出す上の版とは別方式)。
LOG_CHECK_SCRIPTS = {
    "proxy_egress_check": [],       # R1・R4・R9・R10・R31
    "web_recon_burst_check": [],    # R3・R18・R19
    "dns_water_torture_check": [],  # R12
    "container_privilege_check": [],  # R2
    "file_event_check": [],         # R5・R8(設置側)・R20・R28
    "process_tool_check": [],       # R6・R7・R8(起動側)
    "jndi_rce_check": [],           # R29
    "auth_proxy_rotation_check": [],  # R30
    "github_workflow_leak_check": [],  # R27
    "memory_poisoning_check": [],   # R32
}

# /scan/log_checkの結果一覧で、一覧の太字見出し(properties.title)に使う短い表示名。
# vuln_triage.html側のプルダウン(#lc-script)の選択肢と同じ文言(どのRタグ・どんなログか)。
LOG_CHECK_LABELS = {
    "proxy_egress_check": "R1・R4・R9・R10・R31(フォワードプロキシのアクセスログ)",
    "web_recon_burst_check": "R3・R18・R19(Webサーバーのアクセスログ)",
    "dns_water_torture_check": "R12(DNSクエリログ)",
    "container_privilege_check": "R2(コンテナランタイムのイベントログ)",
    "file_event_check": "R5・R8(設置側)・R20・R28(ファイル書き込みイベントログ)",
    "process_tool_check": "R6・R7・R8(起動側)(プロセス実行ログ)",
    "jndi_rce_check": "R29(ネットワーク接続ログ)",
    "auth_proxy_rotation_check": "R30(認証イベントログ)",
    "github_workflow_leak_check": "R27(GitHubイベントログ)",
    "memory_poisoning_check": "R32(混在ログ: memory_write/session_start/egress)",
}


def scan_log_check(body):
    """R1-R32系の「ログファイルを読むだけ」のスクリプトを、利用者が指定した実際のログ
    ファイルに対して実行する。他のボタンと違い、対象はこのPC自身の状態ではなく、利用者が
    明示的に指定したローカルのログファイル1つ(このサーバー自身がローカルでしか待ち受けない
    のと同じ理由で、パスで指定された任意のローカルファイルを読む設計。外部には一切送信しない)。"""
    script = body.get("script")
    if script not in LOG_CHECK_SCRIPTS:
        return {"error": "scriptは次のいずれかを指定してください: %s" % ", ".join(sorted(LOG_CHECK_SCRIPTS))}
    log_path = (body.get("log_path") or "").strip()
    if not log_path:
        return {"error": "ログファイルのパスを指定してください。"}
    if not os.path.isfile(log_path):
        return {"error": "指定されたログファイルが見つかりません: %s" % log_path}

    cmd = [sys.executable, "-I", os.path.join(HERE, "%s.py" % script), "--log-path", log_path]
    cmd += LOG_CHECK_SCRIPTS[script]
    rc, out, err = _run(cmd, cwd=REPO_ROOT, timeout=120)
    text = (out or b"").decode("utf-8", "replace")
    if rc not in (0, 1):
        return {"error": "%s の実行に失敗しました(終了コード%s)。" % (script, rc),
                "returncode": rc, "stderr": err[-2000:]}

    results = []
    if rc == 1:
        results.append({
            "ruleId": script,
            "level": "warning",
            "message": {"text": text[-5000:] or "(ヒットしましたが出力がありませんでした)"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": log_path}}}],
            # properties.title: vuln_triage.html側が一覧の太字見出しに使う短い表示名
            # (無いと「ruleId: ruleId」という意味の無い見出しになる)。
            "properties": {"title": LOG_CHECK_LABELS.get(script, script)},
        })
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": script,
                                "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "results": results,
        }],
        "_skip_reason": "" if rc == 1 else ("%s: 該当するパターンは見つかりませんでした。" % script),
    }


_ARTEX_RESULT_LINE = re.compile(r"^(OK|NG)\s+(.*)$")


def scan_artex_pattern():
    """security-scan/artex-pattern-lab/check_detections.py を実行し、結果をSARIF形式に
    変換して返す(「NG」の項目だけを指摘として載せる)。対象は127.0.0.0/8に固定された、
    このラボ専用の模擬サーバーのみ(本物のLDAP・取引所には一切接続しない。詳細はラボの
    README.ja.md参照)。ポート80での待ち受けに管理者/root権限が必要。"""
    lab_dir = os.path.join(REPO_ROOT, "security-scan", "artex-pattern-lab")
    cmd = [sys.executable, os.path.join(lab_dir, "check_detections.py")]
    rc, out, err = _run(cmd, cwd=lab_dir, timeout=60)
    text = out.decode("utf-8", "replace") if out else ""
    lines = [m.group(1, 2) for l in text.splitlines() if (m := _ARTEX_RESULT_LINE.match(l))]
    if not lines:
        return {"error": "artex-pattern-lab の結果を読み取れませんでした"
                          "(Flaskが入っているか、ポート80が使えるかを確認してください)。",
                "returncode": rc, "stderr": err[-2000:], "stdout": text[-2000:]}
    results = []
    for status, label in lines:
        if status == "NG":
            results.append({
                "ruleId": "artex-pattern-lab/ng", "level": "warning",
                "message": {"text": label},
                "properties": {"title": "ARTEXパターンラボ: " + label},
                "locations": [{"physicalLocation": {"artifactLocation":
                    {"uri": "security-scan/artex-pattern-lab/check_detections.py"}}}],
            })
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "artex-pattern-lab", "rules": []}},
            "results": results,
        }],
    }


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


def _env_hint(name, unix_example, windows_example):
    """環境変数の設定例を、実行中のOSのシェルに合わせて返す(WindowsはPowerShell構文)。"""
    if os.name == "nt":
        return '$env:%s="%s"(PowerShell)' % (name, windows_example)
    return "export %s=%s" % (name, unix_example)


# このサーバーが自動起動した子プロセス。サーバー終了時に止める(残すと次回ポートを塞ぐ)。
_STARTED = []

# 改ざんを検知できる監査ログ(scripts/audit_log.py)。全スキャン要求の「誰が・いつ・何に・
# 同意フラグ付きで」と結果の概要を記録する。検証: python scripts/audit_log.py verify <このファイル>
AUDIT = _load_module(os.path.join(HERE, "audit_log.py"), "audit_log_local")
AUDIT_PATH = os.path.join(RESULTS_DIR, "audit.jsonl")


def _audit_request(body):
    """要求のうち、監査に必要な項目だけを残す(長さも制限する)。"""
    body = body if isinstance(body, dict) else {}
    out = {}
    for k in ("targets", "module", "port", "ports"):
        if k in body:
            out[k] = str(body[k])[:300]
    out["i_own_these"] = body.get("i_own_these") is True
    return out


def _audit_outcome(result):
    if isinstance(result, dict) and "error" in result:
        return {"error": str(result["error"])[:200]}
    if isinstance(result, list):
        return {"items": len(result)}
    if isinstance(result, dict) and isinstance(result.get("runs"), list):
        return {"items": sum(len(r.get("results", [])) for r in result["runs"] if isinstance(r, dict))}
    if isinstance(result, dict) and isinstance(result.get("results"), list):
        return {"items": len(result["results"])}
    return {}


def _ensure_background(cmd, cwd, env, host, port, wait_sec=20):
    """host:port が既に待ち受けていなければ、cmd をバックグラウンドで起動し、
    待ち受け開始まで待つ(最大 wait_sec 秒)。新規に起動したかどうかを返す。"""
    if _port_open(host, port):
        return False
    _STARTED.append(subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                      start_new_session=True))
    deadline = time.monotonic() + wait_sec
    while time.monotonic() < deadline:
        if _port_open(host, port):
            return True
        time.sleep(0.5)
    return True  # 起動は試みた。疎通未確認のまま次に進み、Strix側のエラーに委ねる。


WINDOWS_STRIX_MSG = (
    "Strixは、Windows上で起動したlocal_scan_server.pyからは実行できません(Strixのlocalバックエンドが"
    "Unix専用の部品を使うため。2026-11-02に実機で失敗を確認)。ブラウザとvuln_triage.htmlは"
    "Windowsのままでかまいません。WSL2(Ubuntu)で、もう1つlocal_scan_server.pyを別ポートで起動し"
    "(例: STRIX_LOCAL_DIR=~/strix VULN_APP_PORT=5100 python3 scripts/local_scan_server.py --port 8767)、"
    "画面の接続設定の「Strix用エンドポイント」に http://localhost:8767 を入れてください。"
    "手順: security-scan/strix-local-poc/README.md")


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
    # Windowsネイティブでは、Strixのlocalバックエンド(UnixLocalSandboxClient)がUnix専用のため動かない
    # (2026-11-02の実機で失敗を確認)。数分待たせてから失敗させず、補助プロセスも起動せずに即座に知らせる。
    if os.name == "nt" and os.environ.get("STRIX_ALLOW_WINDOWS", "").strip() != "1":
        return {"error": WINDOWS_STRIX_MSG}
    if body.get("i_own_these") is not True:
        return {"error": "拒否: i_own_these(自社が管理している、または書面で許可を得た対象への"
                          "攻撃実行に同意すること)がtrueである必要があります。"}

    target_ip, err = _resolve_single_target(body)
    if err:
        return err
    target = "%s:%d" % (target_ip, VULN_APP_PORT)

    strix_dir = os.environ.get("STRIX_LOCAL_DIR", "").strip()
    if not strix_dir or not os.path.isdir(strix_dir):
        return {"error": "STRIX_LOCAL_DIRが設定されていないか、ディレクトリが存在しません。"
                          "事前にsecurity-scan/strix-local-poc/README.mdの手順("
                          "git clone https://github.com/usestrix/strix → git checkout v1.7.0 → "
                          "strix-local-backend.patch等を適用 → uv sync)を済ませ、"
                          "local_scan_server.pyを起動する前に同じウィンドウで "
                          + _env_hint("STRIX_LOCAL_DIR", "/path/to/strix", r"C:\path\to\strix")
                          + " のように環境変数を指定してください。"}
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
        vuln_env["VULN_APP_PORT"] = str(VULN_APP_PORT)
        _ensure_background([sys.executable, vuln_app], REPO_ROOT, vuln_env, "127.0.0.1", VULN_APP_PORT)
    elif not _port_open(target_ip, VULN_APP_PORT):
        return {"error": "対象(%s:%d)に接続できません。許可範囲内の別端末を指定した場合は、"
                          "そちら側で対象アプリ(sqli-labのvulnerable_app.pyと同じ"
                          "/loginエンドポイント相当)を先に起動しておいてください。" % (target_ip, VULN_APP_PORT)}
    _ensure_background([sys.executable, mock_llm, "8899", target], REPO_ROOT, dict(os.environ),
                        "127.0.0.1", 8899)

    if not _port_open(target_ip, VULN_APP_PORT) or not _port_open("127.0.0.1", 8899):
        return {"error": "対象(%s:%d)または mock_llm_server.py の起動を確認できませんでした。"
                          "手動で起動してから再試行してください(詳細: " % (target_ip, VULN_APP_PORT) +
                          "security-scan/strix-local-poc/README.md)。"
                          "既定ポートが他のソフトに使われている場合は、環境変数VULN_APP_PORTで"
                          "別のポートを指定できます。"}

    # mock_llm_server.py は前回の実行から起動したまま使い回されることがある。台本の手数カウント
    # (ログ行数)と対象を、今回の実行用にリセットしておく(しないと2回目以降は1手目から
    # finish_scanが返って0件になり、対象を変えても前回の対象へ攻撃コマンドが向かう)。
    mock_state_dir = os.path.join(tempfile.gettempdir(), "mock_llm")
    os.makedirs(mock_state_dir, exist_ok=True)
    open(os.path.join(mock_state_dir, "requests.jsonl"), "w", encoding="utf-8").close()
    with open(os.path.join(mock_state_dir, "target.txt"), "w", encoding="utf-8") as f:
        f.write(target)

    strix_env = dict(os.environ)
    strix_env["STRIX_RUNTIME_BACKEND"] = "local"
    strix_env["STRIX_LLM"] = "openai/mock-model"
    strix_env["OPENAI_API_BASE"] = "http://127.0.0.1:8899/v1"
    strix_env["OPENAI_API_KEY"] = "dummy-mock-key"

    # Strixの「-t ./」は、カレントフォルダの中身を丸ごと実行環境へコピーする。Strixの作業コピー自身
    # (STRIX_LOCAL_DIR)で実行すると、その中の.venvにあるシンボリックリンクをSDKが読めず
    # (LocalDirReadError: symlink_not_supported)、必ず失敗する(2026-11-03、WSL2の実機で発見)。
    # 毎回、シンボリックリンクの無い一時フォルダにsqli-labのコードだけをコピーし、そこから
    # `uv run --project <STRIX_LOCAL_DIR>`で起動する(手動での検証で成功していた手順と同じ)。
    work_dir = tempfile.mkdtemp(prefix="strix-gui-target-")
    lab_dst = os.path.join(work_dir, "security-scan", "sqli-lab")
    os.makedirs(lab_dst)
    lab_src = os.path.dirname(vuln_app)
    for name in sorted(os.listdir(lab_src)):
        src = os.path.join(lab_src, name)
        if name.endswith(".py") and os.path.isfile(src) and not os.path.islink(src):
            shutil.copyfile(src, os.path.join(lab_dst, name))

    before_runs = set()
    runs_dir = os.path.join(work_dir, "strix_runs")

    cmd = ["uv", "run", "--project", strix_dir, "strix", "-n", "-t", "./",
           "--scan-mode", "quick", "--max-budget", "10"]
    try:
        p = subprocess.run(cmd, cwd=work_dir, env=strix_env, capture_output=True,
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
    # Strix自身が"失敗"と記録した実行(例: LLMサーバーに繋がらなかった、サンドボックス起動に
    # 失敗した等)でも、findings.sarif自体は(0件のまま)書き出されてしまう。run.jsonのstatusを
    # 見て、黙って「0件=成功」として返さないようにする。
    run_json_path = os.path.join(runs_dir, run_id, "run.json")
    if os.path.exists(run_json_path):
        try:
            with open(run_json_path, encoding="utf-8") as f:
                run_info = json.load(f)
        except (OSError, ValueError):
            run_info = {}
        status = str(run_info.get("status", "")).lower()
        if "fail" in status or "error" in status:
            log_path = os.path.join(runs_dir, run_id, "strix.log")
            log_tail = ""
            if os.path.exists(log_path):
                with open(log_path, encoding="utf-8", errors="replace") as f:
                    log_tail = f.read()[-2000:]
            hint = ""
            if os.name == "nt":
                hint = ("Windowsで実行しています。strix-local-backend.patchのlocalバックエンドは"
                        "OpenAI Agents SDKのUnixLocalSandboxClient(Unix専用)を使うため、Windowsでは"
                        "サンドボックスの作成で失敗する可能性が高いです。WSL2(Ubuntu等)上での実行を推奨します。")
            return {"error": "Strixの実行自体が失敗しました(run.jsonのstatus=%s、run_id=%s)。"
                              "sarifは0件のまま書き出されるため、これを無視すると見逃します。ログ: %s。%s"
                              % (status, run_id, os.path.join(runs_dir, run_id), hint),
                    "returncode": p.returncode,
                    "stderr": p.stderr.decode("utf-8", "replace")[-2000:],
                    "strix_log_tail": log_tail}
    sarif_path = os.path.join(runs_dir, run_id, "findings.sarif")
    if not os.path.exists(sarif_path):
        return {"error": "findings.sarifが見つかりませんでした(run_id=%s)。"
                          "脆弱性が検出されなかった可能性があります。" % run_id,
                "returncode": p.returncode}
    with open(sarif_path, encoding="utf-8") as f:
        result = json.load(f)
    # 成功時だけ一時フォルダを消す(失敗時は、ログを調べられるよう残す)
    shutil.rmtree(work_dir, ignore_errors=True)
    return result


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
                          "済ませ、local_scan_server.pyを起動する前に同じウィンドウで "
                          + _env_hint("CAIRN_LOCAL_DIR", "/path/to/Cairn", r"C:\path\to\Cairn")
                          + " のように環境変数を指定してください。"}
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
        vuln_env["VULN_APP_PORT"] = str(VULN_APP_PORT)
        _ensure_background([sys.executable, vuln_app], REPO_ROOT, vuln_env, "127.0.0.1", VULN_APP_PORT)
    elif not _port_open(target_ip, VULN_APP_PORT):
        return {"error": "対象(%s:%d)に接続できません。許可範囲内の別端末を指定した場合は、"
                          "そちら側で対象アプリ(sqli-labのvulnerable_app.pyと同じ"
                          "/loginエンドポイント相当)を先に起動しておいてください。" % (target_ip, VULN_APP_PORT)}

    cairn_env = dict(os.environ)
    cairn_env.setdefault("UV_DEFAULT_INDEX", "https://pypi.org/simple")
    _ensure_background(
        ["uv", "run", "--project", "cairn", "cairn", "serve", "--host", "127.0.0.1",
         "--port", str(CAIRN_SERVE_PORT)],
        cairn_dir, cairn_env, "127.0.0.1", CAIRN_SERVE_PORT, wait_sec=30)

    if not _port_open(target_ip, VULN_APP_PORT) or not _port_open("127.0.0.1", CAIRN_SERVE_PORT):
        return {"error": "対象(%s:%d)または cairn serve の起動を確認できませんでした。"
                          "手動で起動してから再試行してください(詳細: " % (target_ip, VULN_APP_PORT) +
                          "security-scan/cairn-lab/cairn-authorized-lab-runbook.md)。"
                          "既定ポートが他のソフトに使われている場合は、環境変数VULN_APP_PORTで"
                          "別のポートを指定できます。"}

    cmd = [sys.executable, run_script, "--cairn-src", cairn_src,
           "--base-url", "http://127.0.0.1:%d" % CAIRN_SERVE_PORT,
           "--target", "http://%s:%d" % (target_ip, VULN_APP_PORT)]
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
                  else "http://%s:%d/login" % (target_ip, VULN_APP_PORT))
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


def scan_multiproto(body):
    """zgrab2本体が無くても使える、SSH/FTP/Telnet/SMTP/Redis等の複数プロトコルの軽量な代替
    (scripts/multi_proto_lite.py)。zgrab2と同じ同意フラグ(i_own_these)・許可範囲判定が無いと
    一切実行しない。出力はzgrab2の各モジュールと互換の形式で返すため、GUI側の取り込みロジック
    (zgrab2として自動判別)をそのまま再利用できる。"""
    body = body or {}
    if body.get("i_own_these") is not True:
        return {"error": "拒否: i_own_these(自社が管理している、または書面で許可を得た対象であること)が"
                          "trueである必要があります。"}
    targets_text = str(body.get("targets", "") or "")
    if not targets_text.strip():
        return {"error": "対象を入力してください。"}
    mpl = _load_module(os.path.join(HERE, "multi_proto_lite.py"), "multi_proto_lite_local")
    module = str(body.get("module", "") or "ssh").strip().lower()
    if module not in mpl.DEFAULT_PORTS:
        return {"error": "未対応のモジュールです: %s(対応: %s)" % (module, ", ".join(sorted(mpl.DEFAULT_PORTS)))}
    port = body.get("port")
    try:
        port = int(port) if port not in (None, "") else None
    except (TypeError, ValueError):
        return {"error": "portは数値で指定してください。"}
    nc = _load_module(os.path.join(REPO_ROOT, "netcheck", "netcheck.py"), "netcheck_local_for_multiproto")
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
    rows = []
    for name, ip in ok:
        host = name if name != ip else None
        rows.append(mpl.grab_target(module, ip, port=port, host=host, timeout=5.0))
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
    zgrab2_bin = _ensure_zgrab2()
    if zgrab2_bin is None:
        return {"error": "zgrab2本体がこの機器にインストールされていません。Go(https://go.dev)が"
                          "入っていれば自動ビルドを試みますが、今回は失敗したか、goコマンド自体が"
                          "見つかりませんでした。手動で入れる場合は go install "
                          "github.com/zmap/zgrab2/cmd/zgrab2@latest を実行してください。"
                          "(許可範囲チェックは通過しました: %s)" % ", ".join(lines)}
    module = str(body.get("module", "http") or "http")
    cmd = [zgrab2_bin, module]
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
    "/scan/dep_cve": lambda body: scan_dep_cve(),
    "/scan/artex_pattern": lambda body: scan_artex_pattern(),
    "/scan/os_patch": lambda body: scan_os_patch(),
    "/scan/node_version": lambda body: scan_node_version(),
    "/scan/python_brotli": lambda body: scan_python_brotli(),
    "/scan/php_version": lambda body: scan_php_version(),
    "/scan/bind_version": lambda body: scan_bind_version(),
    "/scan/f5_bigip_apm": lambda body: scan_f5_bigip_apm(),
    "/scan/java_cacerts_emudhra": lambda body: scan_java_cacerts_emudhra(),
    "/scan/linux_kernel_cve202698432": lambda body: scan_linux_kernel_cve202698432(),
    "/scan/linux_kernel_infinitycore": lambda body: scan_linux_kernel_infinitycore(),
    "/scan/sqli_lab_regression": lambda body: scan_sqli_lab_regression(),
    "/scan/detection_regression": lambda body: scan_detection_regression(),
    "/scan/local_selfcheck": lambda body: scan_local_selfcheck(),
    "/scan/log_check": lambda body: scan_log_check(body),
    "/scan/netcheck": lambda body: scan_netcheck(body),
    "/scan/zgrab2": lambda body: scan_zgrab2(body),
    "/scan/httplite": lambda body: scan_httplite(body),
    "/scan/multiproto": lambda body: scan_multiproto(body),
    "/scan/strix": lambda body: scan_strix(body),
    "/scan/cairn": lambda body: scan_cairn(body),
}

_LOCK = threading.Lock()  # 一度に1つのスキャンだけ(同じツールの結果ファイルを使い回すため)


class _NullLock:
    """_LOCKを取らないエンドポイント(local_selfcheck)用の、何もしないコンテキストマネージャ。"""
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


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
            return self._send(200, {"status": "ok", "repo_root": REPO_ROOT,
                                    "platform": "windows" if os.name == "nt" else sys.platform,
                                    "strix_supported": os.name != "nt"
                                    or os.environ.get("STRIX_ALLOW_WINDOWS", "").strip() == "1"})
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
        req = _audit_request(body)
        # 実行前に記録する。書けない場合は実行しない(能動スキャンが記録なしで走らないように)。
        try:
            start = AUDIT.append(AUDIT_PATH, {"event": "scan_start", "endpoint": self.path,
                                              "client": self.client_address[0],
                                              "origin": self.headers.get("Origin", ""), "request": req})
        except Exception as e:  # noqa
            return self._send(500, {"error": "監査ログ(%s)に書き込めないため、実行しません: %s" % (AUDIT_PATH, e)})
        t0 = time.monotonic()
        # /scan/local_selfcheckは、このサーバー自身へ(/health・/scan/netcheck・/scan/httplite等)
        # 別のHTTPリクエストとして問い合わせる設計(local_scan_selfcheck.py自身の挙動)。それらの
        # 先がここと同じ_LOCKを取ろうとするため、ここで_LOCKを取ったままだとデッドロックする。
        # この1エンドポイントだけ_LOCKの対象から外す(実行する処理自体は他のスキャンを起動しない、
        # 読み取り専用の自己診断のため、同時実行による競合の実害も無い)。
        use_lock = self.path != "/scan/local_selfcheck"
        lock_ctx = _LOCK if use_lock else _NullLock()
        with lock_ctx:
            try:
                result = ROUTES[self.path](body)
            except Exception as e:  # noqa
                result, code = {"error": "内部エラー: %s" % e}, 500
            else:
                code = 400 if isinstance(result, dict) and "error" in result else 200
        try:
            AUDIT.append(AUDIT_PATH, {"event": "scan_end", "endpoint": self.path, "start_seq": start["seq"],
                                      "status": code, "duration_ms": int((time.monotonic() - t0) * 1000),
                                      "outcome": _audit_outcome(result)})
        except Exception as e:  # noqa
            sys.stderr.write("警告: 監査ログ(scan_end)の書き込みに失敗しました: %s\n" % e)
        self._send(code, result)


def main():
    global AUDIT_PATH, SERVER_PORT
    ap = argparse.ArgumentParser(description="vuln_triage.html から、このリポジトリ自身を対象に"
                                              "各診断ツールを実際に呼び出す、ローカル専用の補助サーバー")
    ap.add_argument("--port", type=int, default=8766, help="待ち受けポート(既定 8766)")
    a = ap.parse_args()
    SERVER_PORT = a.port
    os.makedirs(RESULTS_DIR, exist_ok=True)
    if a.port != 8766:
        # 2つ目のサーバー(例: WSL2でStrix用に8767で起動)が同じ作業フォルダを使うと、同じ監査ログへ
        # 別プロセスから同時に追記して番号が重複し、検証がNGになる(プロセス内のロックは効かない)。
        # ポートごとに別ファイルへ記録する。
        AUDIT_PATH = os.path.join(RESULTS_DIR, "audit-%d.jsonl" % a.port)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print("local_scan_server: http://127.0.0.1:%d で待ち受け中(Ctrl+Cで終了)" % a.port)
    print("対象リポジトリ: %s" % REPO_ROOT)
    for name in ("STRIX_LOCAL_DIR", "CAIRN_LOCAL_DIR"):
        v = os.environ.get(name, "").strip()
        state = ("OK: %s" % v) if v and os.path.isdir(v) else (
            "フォルダが見つかりません: %s" % v if v else "未設定(このボタンは使えません)")
        print("%s: %s" % (name, state))
    if os.name == "nt":
        print("注意: Windows上のこのサーバーではStrixを実行できません(他のボタンは使えます)。"
              "StrixはWSL2で別ポートのサーバーを起動して使います(詳細はStrixボタンのエラー表示を参照)。")
    print("sqli-labデモアプリのポート(VULN_APP_PORT): %d" % VULN_APP_PORT)
    print("監査ログ: %s" % AUDIT_PATH)
    print("vuln_triage.html の「ローカルスキャナーを呼び出す」から利用してください。")
    AUDIT.append(AUDIT_PATH, {"event": "server_start", "port": a.port, "vuln_app_port": VULN_APP_PORT,
                              "strix_dir_set": bool(os.environ.get("STRIX_LOCAL_DIR")),
                              "cairn_dir_set": bool(os.environ.get("CAIRN_LOCAL_DIR"))})
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        AUDIT.append(AUDIT_PATH, {"event": "server_stop"})
        for p in _STARTED:
            if p.poll() is None:
                p.terminate()


if __name__ == "__main__":
    sys.exit(main())
