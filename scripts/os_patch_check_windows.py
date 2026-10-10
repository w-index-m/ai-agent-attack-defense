#!/usr/bin/env python3
"""os_patch_check_windows: Windows の機器で、更新の状態を確認し SARIF(2.1.0) に書き出す(確認専用)。

  - 既定(--windows-pending を付けない): 適用済みの更新(HotFix)を一覧(Get-HotFix)。
      読み取りだけ。管理者権限は通常いらない。
  - --windows-pending: 未適用の更新も調べる(Windows Update API)。時間がかかることがある。
      管理者で実行すると取れることがある。
  - 出力: SARIF 2.1.0。vuln_triage.html にそのまま読み込める。

安全のための制限:
  - **確認だけ**。更新の適用・設定の変更・ネットワークへの送信は一切しない。
  - 実行するのは、このPCの PowerShell の読み取りコマンドだけ(リモートには接続しない)。
  - 出力はローカルのファイルだけ。自分が管理するPCでだけ実行すること。

使い方:
    python scripts/os_patch_check_windows.py --out os_patch_windows.sarif
    python scripts/os_patch_check_windows.py --windows-pending --out os_patch_windows.sarif

標準ライブラリだけで動く(Python 3.8 以上)。RHEL 系は scripts/os_patch_check_linux.py。
"""
import argparse
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "os-patch-check-windows"

PS_HOTFIX = (
    "Get-HotFix | Select-Object HotFixID,Description,InstalledOn,Caption | "
    "ConvertTo-Json -Depth 2"
)
# 未適用(保留中)の更新を、Windows Update API で調べる。
PS_PENDING = (
    "$s=New-Object -ComObject Microsoft.Update.Session; "
    "$r=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0'); "
    "$r.Updates | ForEach-Object { [pscustomobject]@{Title=$_.Title; "
    "MsrcSeverity=$_.MsrcSeverity; KB=($_.KBArticleIDs -join ',')} } | ConvertTo-Json -Depth 2"
)
SEV_MAP = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}


def run_ps(script):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return None, "PowerShell が見つかりません。Windows の PC で実行してください。"
    try:
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "PowerShell の実行に失敗しました: %s" % e
    if r.returncode != 0:
        return None, "PowerShell の実行に失敗しました: %s" % (r.stderr.strip() or r.stdout.strip())
    return r.stdout, None


def as_list(text):
    """PowerShell の JSON は、1件だと配列でなく単一オブジェクトになるので、両方に対応する。"""
    if not text.strip():
        return []
    data = json.loads(text)
    return data if isinstance(data, list) else [data]


def hotfix_findings():
    out, err = run_ps(PS_HOTFIX)
    if err:
        return None, err
    findings = []
    for it in as_list(out):
        hid = it.get("HotFixID") or ""
        desc = it.get("Description") or ""
        findings.append({
            "rule": "windows-hotfix-installed", "level": "note", "label": "info",
            "title": "適用済み %s %s" % (hid, desc),
            "message": "適用済みの更新(HotFix): %s %s (%s)" % (hid, desc, it.get("InstalledOn") or ""),
        })
    return findings, None


def pending_findings():
    out, err = run_ps(PS_PENDING)
    if err:
        return None, err + "(管理者として実行すると取れることがあります)"
    findings = []
    for it in as_list(out):
        sev = (it.get("MsrcSeverity") or "").lower()
        label = SEV_MAP.get(sev, "medium")
        findings.append({
            "rule": "windows-pending-update",
            "level": "error" if label in ("critical", "high") else "warning",
            "label": label,
            "title": "未適用 %s %s" % (it.get("KB") or "", it.get("Title") or ""),
            "message": "未適用の更新: %s (重大度 %s) KB:%s" % (it.get("Title") or "", sev or "未分類", it.get("KB") or "-"),
        })
    return findings, None


def to_sarif(findings, host):
    results = []
    for f in findings:
        results.append({
            "ruleId": f["rule"],
            "level": f["level"],
            "message": {"text": f["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "windows:update"}}}],
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
    ap = argparse.ArgumentParser(description="Windows: 更新の状態を SARIF に書き出す(確認専用)")
    ap.add_argument("--windows-pending", action="store_true", help="未適用の更新も調べる(時間がかかることがある)")
    ap.add_argument("--out", default="os_patch_windows.sarif", help="出力先(既定: os_patch_windows.sarif)")
    a = ap.parse_args()

    if platform.system() != "Windows":
        print("エラー: このスクリプトは Windows 用です。RHEL 系は os_patch_check_linux.py を使ってください。",
              file=sys.stderr)
        return 2

    findings, err = hotfix_findings()
    if err:
        print("エラー: " + err, file=sys.stderr)
        return 2
    if a.windows_pending:
        found, err = pending_findings()
        if err:
            print("エラー: " + err, file=sys.stderr)
            return 2
        findings += found

    host = platform.node() or "unknown-host"
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(to_sarif(findings, host), f, ensure_ascii=False, indent=2)
    pending = [x for x in findings if x["rule"] != "windows-hotfix-installed"]
    print("%s を書き出しました。(%d 件。うち未適用 %d 件)" % (a.out, len(findings), len(pending)))
    print("次は vuln_triage.html にこのファイルを読み込んでください。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
