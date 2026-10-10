#!/usr/bin/env python3
"""os_patch_check: 自分の機器の OS 更新状態を確認し、結果を SARIF(2.1.0) に書き出す(確認専用)。

  - RHEL 系(dnf)       : 未適用のセキュリティ更新を一覧(dnf updateinfo list security --available)
  - Windows            : 適用済みの更新(HotFix)を一覧(Get-HotFix)。
                         未適用の確認は Windows Update API を使う(--windows-pending)。
  - 出力は SARIF 2.1.0。vuln_triage.html にそのまま読み込める。

安全のための制限:
  - **確認だけ**。更新の適用・設定の変更・ネットワークへの送信は一切しない。
  - 実行しているのは、そのホスト自身のコマンドだけ(リモートには接続しない)。
  - 出力はローカルのファイルだけ。外部へは送らない。
  - 自分が管理する機器でだけ実行すること。

使い方:
    # RHEL 系(dnf のある機器)
    python3 scripts/os_patch_check.py --rhel --out os_patch.sarif

    # Windows(PowerShell を呼ぶ。管理者でなくても HotFix の一覧は取れる)
    python3 scripts/os_patch_check.py --windows --out os_patch.sarif
    python3 scripts/os_patch_check.py --windows --windows-pending --out os_patch.sarif

    # 結果は vuln_triage.html に読み込む(ツールは SARIF として判別される)

標準ライブラリだけで動く(Python 3.8 以上)。
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
DRIVER = "os-patch-check"


def run(cmd, timeout=180):
    """コマンドを実行して (returncode, stdout, stderr) を返す。見つからなければ None。"""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return (1, "", str(e))
    return (r.returncode, r.stdout, r.stderr)


# --- RHEL 系: 未適用のセキュリティ更新 --------------------------------------------

# 例: "RHSA-2026:1234 Important/Sec. kernel-5.14.0-1.el9.x86_64"
RHEL_LINE = re.compile(r"^(RHSA-\d{4}:\d+|[A-Z]+-\d{4}:\d+)\s+(\w+)/Sec\.\s+(\S+)")
RHEL_SEV = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}


def rhel_findings():
    res = run(["dnf", "updateinfo", "list", "security", "--available"])
    if res is None:
        return None, "dnf が見つかりません(RHEL 系の機器で実行してください)。"
    rc, out, err = res
    if rc not in (0, 100):  # dnf は更新がある場合 100 を返す
        return None, "dnf の実行に失敗しました: %s" % (err.strip() or out.strip())
    findings = []
    for line in out.splitlines():
        m = RHEL_LINE.match(line.strip())
        if not m:
            continue
        advisory, sev, pkg = m.group(1), m.group(2).lower(), m.group(3)
        findings.append({
            "rule": "rhel-security-update",
            "level": "error" if RHEL_SEV.get(sev, "medium") in ("critical", "high") else "warning",
            "message": "未適用のセキュリティ更新: %s (%s) — %s" % (advisory, sev, pkg),
            "title": "%s %s" % (advisory, pkg),
            "uri": "dnf:installed", "line": None,
            "severity_label": RHEL_SEV.get(sev, "medium"),
        })
    return findings, None


# --- Windows: HotFix(適用済み)と、未適用の更新 --------------------------------------

PS_HOTFIX = (
    "Get-HotFix | Select-Object HotFixID,Description,InstalledOn,Caption | "
    "ConvertTo-Json -Depth 2"
)
# 未適用(保留中)の更新を、Windows Update API で調べる。管理者権限が要ることがある。
PS_PENDING = (
    "$s=New-Object -ComObject Microsoft.Update.Session; "
    "$r=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0'); "
    "$r.Updates | ForEach-Object { [pscustomobject]@{Title=$_.Title; "
    "MsrcSeverity=$_.MsrcSeverity; KB=($_.KBArticleIDs -join ',')} } | ConvertTo-Json -Depth 2"
)


def ps(script):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return None, "PowerShell が見つかりません(Windows で実行してください)。"
    try:
        r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", script],
                           capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "PowerShell の実行に失敗しました: %s" % e
    if r.returncode != 0:
        return None, "PowerShell の実行に失敗しました: %s" % (r.stderr.strip() or r.stdout.strip())
    return r.stdout, None


def as_list(text):
    if not text.strip():
        return []
    data = json.loads(text)
    return data if isinstance(data, list) else [data]


def windows_hotfix_findings():
    out, err = ps(PS_HOTFIX)
    if err:
        return None, err
    items = as_list(out)
    # 適用済みの更新は「指摘」ではなく、確認用の記録として info で出す
    findings = []
    for it in items:
        hid = it.get("HotFixID") or ""
        findings.append({
            "rule": "windows-hotfix-installed", "level": "note",
            "message": "適用済みの更新(HotFix): %s %s (%s)" % (hid, it.get("Description") or "", it.get("InstalledOn") or ""),
            "title": "適用済み %s %s" % (hid, it.get("Description") or ""),
            "uri": "windows:hotfix", "line": None, "severity_label": "info",
        })
    return findings, None


def windows_pending_findings():
    out, err = ps(PS_PENDING)
    if err:
        return None, err + " (管理者として実行すると取れることがあります)"
    items = as_list(out)
    findings = []
    for it in items:
        sev = (it.get("MsrcSeverity") or "").lower()
        label = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}.get(sev, "medium")
        findings.append({
            "rule": "windows-pending-update",
            "level": "error" if label in ("critical", "high") else "warning",
            "message": "未適用の更新: %s (重大度 %s) KB:%s" % (it.get("Title") or "", sev or "未分類", it.get("KB") or "-"),
            "title": "未適用 %s %s" % (it.get("KB") or "", it.get("Title") or ""),
            "uri": "windows:wua", "line": None, "severity_label": label,
        })
    return findings, None


# --- SARIF 2.1.0 に書き出す --------------------------------------------------------

def to_sarif(findings, host):
    results = []
    for f in findings:
        result = {
            "ruleId": f["rule"],
            "level": f["level"],
            "message": {"text": f["message"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["uri"]}}}],
            "properties": {"severityLabel": f["severity_label"], "host": host,
                           "title": f.get("title") or f["rule"]},
        }
        results.append(result)
    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {"name": DRIVER, "informationUri": "https://github.com/w-index-m/ai-agent-attack-defense"}},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": datetime.now(timezone.utc).isoformat(timespec="seconds")}],
            "results": results,
        }],
    }


def main():
    ap = argparse.ArgumentParser(description="自分の機器の OS 更新状態を確認し、SARIF に書き出す(確認専用)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--rhel", action="store_true", help="RHEL 系: 未適用のセキュリティ更新を一覧")
    g.add_argument("--windows", action="store_true", help="Windows: 適用済み HotFix を一覧")
    ap.add_argument("--windows-pending", action="store_true", help="--windows と併用: 未適用の更新も調べる")
    ap.add_argument("--out", default="os_patch.sarif", help="出力先(既定: os_patch.sarif)")
    a = ap.parse_args()

    host = platform.node() or "unknown-host"
    findings = []

    if a.rhel:
        found, err = rhel_findings()
        if err:
            print("エラー: " + err, file=sys.stderr)
            return 2
        findings += found
    else:
        found, err = windows_hotfix_findings()
        if err:
            print("エラー: " + err, file=sys.stderr)
            return 2
        findings += found
        if a.windows_pending:
            found, err = windows_pending_findings()
            if err:
                print("エラー: " + err, file=sys.stderr)
                return 2
            findings += found

    doc = to_sarif(findings, host)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    pending = [f for f in findings if f["rule"] != "windows-hotfix-installed"]
    print("%s を書き出しました。(%d 件。うち未適用 %d 件)" % (a.out, len(findings), len(pending)))
    print("次は vuln_triage.html にこのファイルを読み込んでください。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
