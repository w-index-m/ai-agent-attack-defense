#!/usr/bin/env python3
"""os_patch_check_linux: RHEL 系の機器で、未適用のセキュリティ更新を確認し SARIF(2.1.0) に書き出す(確認専用)。

  - 対象: dnf のある機器(RHEL / Rocky / AlmaLinux 等)。
  - 確認するもの: 未適用のセキュリティ更新(RHSA)を一覧(dnf updateinfo list security --available)。
  - 出力: SARIF 2.1.0。vuln_triage.html にそのまま読み込める。

安全のための制限:
  - **確認だけ**。更新の適用・設定の変更・ネットワークへの送信は一切しない。
  - 実行するのは、このホストの dnf だけ(リモートには接続しない)。
  - 出力はローカルのファイルだけ。自分が管理する機器でだけ実行すること。

使い方:
    python3 scripts/os_patch_check_linux.py --out os_patch.sarif

標準ライブラリだけで動く(Python 3.8 以上)。Windows 用は scripts/os_patch_check_windows.py。
"""
import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "os-patch-check-linux"

# 例: "RHSA-2026:1234 Important/Sec. kernel-5.14.0-1.el9.x86_64"
RHEL_LINE = re.compile(r"^(RHSA-\d{4}:\d+|[A-Z]+-\d{4}:\d+)\s+(\w+)/Sec\.\s+(\S+)")
SEV_MAP = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}


def pending_security_updates():
    """未適用のセキュリティ更新を返す。(findings, error) のどちらか一方が None。"""
    if shutil.which("dnf") is None:
        return None, "dnf が見つかりません。RHEL / Rocky / AlmaLinux など、dnf のある機器で実行してください。"
    try:
        r = subprocess.run(["dnf", "updateinfo", "list", "security", "--available"],
                           capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "dnf の実行に失敗しました: %s" % e
    # dnf は、更新がある場合に終了コード 100 を返す。これは失敗ではない。
    if r.returncode not in (0, 100):
        return None, "dnf の実行に失敗しました: %s" % (r.stderr.strip() or r.stdout.strip())

    findings = []
    for line in r.stdout.splitlines():
        m = RHEL_LINE.match(line.strip())
        if not m:
            continue
        advisory, sev, pkg = m.group(1), m.group(2).lower(), m.group(3)
        label = SEV_MAP.get(sev, "medium")
        findings.append({
            "rule": "rhel-security-update",
            "level": "error" if label in ("critical", "high") else "warning",
            "title": "%s %s" % (advisory, pkg),
            "message": "未適用のセキュリティ更新: %s (%s) — %s" % (advisory, sev, pkg),
            "label": label,
        })
    return findings, None


def to_sarif(findings, host):
    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule"],
            "level": f["level"],
            "message": {"text": f["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "dnf:installed"}}}],
            "properties": {"severityLabel": f["label"], "host": host, "title": f["title"]},
        })
    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {"name": DRIVER,
                                "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": datetime.now(timezone.utc).isoformat(timespec="seconds")}],
            "results": results,
        }],
    }


def main():
    ap = argparse.ArgumentParser(description="RHEL 系: 未適用のセキュリティ更新を SARIF に書き出す(確認専用)")
    ap.add_argument("--out", default="os_patch_linux.sarif", help="出力先(既定: os_patch_linux.sarif)")
    a = ap.parse_args()

    findings, err = pending_security_updates()
    if err:
        print("エラー: " + err, file=sys.stderr)
        return 2

    host = platform.node() or "unknown-host"
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(to_sarif(findings, host), f, ensure_ascii=False, indent=2)
    print("%s を書き出しました。(未適用のセキュリティ更新 %d 件)" % (a.out, len(findings)))
    print("次は vuln_triage.html にこのファイルを読み込んでください。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
