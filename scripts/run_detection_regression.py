"""run_detection_regression: scripts/配下の「ログを読むだけの検知スクリプト」が壊れていないかの
回帰テスト(sqli-lab/run_regression.pyと同じ考え方のCI回帰、こちらはこのリポジトリ自身の
スクリプト本体)。

対象は2種類、security-scan/detection-fixtures/<スクリプト名>/配下の合成ログ(positive.*/
negative.*)に対して実行する:

  1. R1-R31系の「ログを読み、終了コード0(ヒット無し)/1(ヒット有り)/2(読み取り失敗)を返す」
     スクリプト9本: positive入力で終了コード1、negative入力で終了コード0になることを確認。
  2. CVEバージョン照合系の「--log-path/--outでSARIFを書き出す」スクリプト8本: これらは
     設計上、終了コードが常に0(確認専用で、何を見つけてもCIを止めない)なので、代わりに
     --outで書き出したSARIFの中身(指定したruleIdの有無、またはseverityLabel)を見る。

対象外(このスクリプトでは検証しない。理由は各々異なる):
  - netcheck/netcheck.py・scripts/local_scan_server.py/local_scan_selfcheck.py・
    multi_proto_lite.py・http_lite_banner.py・scripts/zgrab2_guard.py: 「人間が自分の実環境に
    対して手動実行する」設計で、ログ読み取りモードを持たない(実際のネットワーク・プロセスを
    伴うため、このリポジトリのCIでは意図的に対象外のまま)。
  - scripts/os_patch_check_linux.py/_windows.py: 実行しているホスト自身のOSパッチ状態を見る
    ツールで、合成ログでの再現モードを持たない。
  - scripts/patch_suggest.py: LLMエンドポイントへの問い合わせが前提で、オフラインの合成入力
    だけでは再現できない(本リポジトリの既定方針どおり、LLM呼び出しを前提にしたCI回帰は作らない)。

安全のための制限: 対象スクリプトの実行(subprocess)以外、ネットワーク通信・ファイルの変更は
一切しない。

使い方:
  python3 scripts/run_detection_regression.py
  python3 scripts/run_detection_regression.py --out results/detection_regression.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "security-scan" / "detection-fixtures"
SCRIPTS = ROOT / "scripts"


def run(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-I", *args], capture_output=True, text=True, cwd=ROOT, timeout=60
    )
    return proc.returncode, proc.stdout + proc.stderr


# --------------------------------------------------------------------------
# 1. 終了コード(0/1)で判定するスクリプト(R1-R31系)
# --------------------------------------------------------------------------

# (スクリプト名, positive/negativeに追加で渡すCLI引数)
EXIT_CODE_CASES: list[tuple[str, list[str]]] = [
    ("proxy_egress_check", ["--format", "jsonl"]),
    ("web_recon_burst_check", ["--format", "jsonl"]),
    ("dns_water_torture_check", ["--subdomain-threshold", "5", "--nxdomain-ratio", "0.5"]),
    ("container_privilege_check", []),
    ("file_event_check", []),
    ("process_tool_check", []),
    ("jndi_rce_check", []),
    ("auth_proxy_rotation_check", ["--threshold", "3"]),
    ("github_workflow_leak_check", []),
]


def check_exit_code_case(name: str, extra_args: list[str]) -> list[dict]:
    script = SCRIPTS / f"{name}.py"
    findings = []
    for case, expect_hit in (("positive", True), ("negative", False)):
        log_path = FIXTURES / name / f"{case}.jsonl"
        rc, output = run([str(script), "--log-path", str(log_path), *extra_args])
        got_hit = rc == 1
        if rc not in (0, 1):
            findings.append({
                "severity": "high",
                "title": "regression: %s が %s 入力でエラー終了(終了コード%d)" % (name, case, rc),
                "location": str(log_path),
                "detail": output[-500:],
            })
        elif got_hit != expect_hit:
            findings.append({
                "severity": "high",
                "title": "regression: %s が %s 入力を誤判定" % (name, case),
                "location": str(log_path),
                "detail": "expected hit=%s, got hit=%s (exit %d)" % (expect_hit, got_hit, rc),
            })
    return findings


# --------------------------------------------------------------------------
# 2. SARIF出力の中身(指定したruleIdの有無)で判定するスクリプト
# --------------------------------------------------------------------------

# (スクリプト名, --log-pathに渡すCLIフラグ名, 見るべきruleId)
SARIF_PRESENCE_CASES: list[tuple[str, str, str]] = [
    ("bind_version_check", "--log-path", "bind-log-assertion-near-gsstsig"),
    ("java_cacerts_emudhra_check", "--log-path", "java-tls-failure-near-emudhra-root"),
    ("linux_kernel_cve202698432_check", "--log-path", "linux-kernel-cve-2026-98432-crash-lead"),
    ("linux_kernel_infinitycore_check", "--log-path", "linux-kernel-infinitycore-crash-lead"),
    ("php_version_check", "--log-path", "php-fpm-worker-crash"),
    ("python_brotli_check", "--log-path", "python-brotli-worker-crash"),
    ("node_version_check", "--log-path", "node-brotli-worker-crash"),
]


def check_sarif_presence_case(name: str, flag: str, rule_id: str, out_dir: Path) -> list[dict]:
    script = SCRIPTS / f"{name}.py"
    findings = []
    for case, expect_present in (("positive", True), ("negative", False)):
        log_path = FIXTURES / name / f"{case}.log"
        out_path = out_dir / f"{name}_{case}.sarif"
        rc, output = run([str(script), flag, str(log_path), "--out", str(out_path)])
        if rc != 0:
            findings.append({
                "severity": "high",
                "title": "regression: %s が %s 入力でエラー終了(終了コード%d)" % (name, case, rc),
                "location": str(log_path),
                "detail": output[-500:],
            })
            continue
        try:
            with open(out_path, encoding="utf-8") as f:
                sarif = json.load(f)
            present = any(r.get("ruleId") == rule_id for r in sarif["runs"][0]["results"])
        except (OSError, json.JSONDecodeError, KeyError, IndexError) as exc:
            findings.append({
                "severity": "high",
                "title": "regression: %s の %s 入力でSARIF出力を読めなかった" % (name, case),
                "location": str(out_path),
                "detail": str(exc),
            })
            continue
        if present != expect_present:
            findings.append({
                "severity": "high",
                "title": "regression: %s が %s 入力を誤判定(ruleId=%s)" % (name, case, rule_id),
                "location": str(log_path),
                "detail": "expected present=%s, got present=%s" % (expect_present, present),
            })
    return findings


def check_f5_bigip_apm_case(out_dir: Path) -> list[dict]:
    """f5_bigip_apm_check.pyはチェックごとに常に1件のSARIF resultを出すため、ruleIdの
    有無ではなく properties.severityLabel で判定する(他の7本とは異なる構造)。"""
    script = SCRIPTS / "f5_bigip_apm_check.py"
    findings = []
    for case, expect_high in (("positive", True), ("negative", False)):
        log_path = FIXTURES / "f5_bigip_apm_check" / f"{case}.log"
        out_path = out_dir / f"f5_bigip_apm_check_{case}.sarif"
        rc, output = run([
            str(script), "--apm-log", str(log_path),
            "--core-dir", "/nonexistent-core-dir-for-ci-regression",
            "--tmm-finish", "/nonexistent-tmm-finish-for-ci-regression",
            "--out", str(out_path),
        ])
        if rc != 0:
            findings.append({
                "severity": "high",
                "title": "regression: f5_bigip_apm_check が %s 入力でエラー終了(終了コード%d)" % (case, rc),
                "location": str(log_path),
                "detail": output[-500:],
            })
            continue
        try:
            with open(out_path, encoding="utf-8") as f:
                sarif = json.load(f)
            sev = next(
                r["properties"]["severityLabel"]
                for r in sarif["runs"][0]["results"]
                if r.get("ruleId") == "f5-bigip-apm-apm-log"
            )
        except (OSError, json.JSONDecodeError, KeyError, IndexError, StopIteration) as exc:
            findings.append({
                "severity": "high",
                "title": "regression: f5_bigip_apm_check の %s 入力でSARIF出力を読めなかった" % case,
                "location": str(out_path),
                "detail": str(exc),
            })
            continue
        got_high = sev == "high"
        if got_high != expect_high:
            findings.append({
                "severity": "high",
                "title": "regression: f5_bigip_apm_check が %s 入力を誤判定" % case,
                "location": str(log_path),
                "detail": "expected severity=high:%s, got severityLabel=%s" % (expect_high, sev),
            })
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="", help="findingsをJSONで書き出す場所(省略可)")
    args = ap.parse_args()

    findings: list[dict] = []
    tmp_out_dir = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "detection-regression-sarif"
    tmp_out_dir.mkdir(parents=True, exist_ok=True)

    total_checks = len(EXIT_CODE_CASES) + len(SARIF_PRESENCE_CASES) + 1

    for name, extra_args in EXIT_CODE_CASES:
        findings.extend(check_exit_code_case(name, extra_args))
    for name, flag, rule_id in SARIF_PRESENCE_CASES:
        findings.extend(check_sarif_presence_case(name, flag, rule_id, tmp_out_dir))
    findings.extend(check_f5_bigip_apm_case(tmp_out_dir))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)

    if findings:
        print("%d regression(s) found in these detection scripts:" % len(findings))
        for item in findings:
            print("  [%s] %s: %s" % (item["severity"], item["title"], item["detail"]))
        return 1

    print(
        "OK: all %d detection scripts classified their positive/negative fixtures correctly."
        % total_checks
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
