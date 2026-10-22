#!/usr/bin/env python3
"""f5_bigip_apm_check: F5 BIG-IP APMで、OAuth UserInfoのヒープバッファオーバーフロー
(CVE-2026-94127、CVSS 9.8、事前認証不要RCE、悪用確認済み)の対象になりうるか、または
侵害の兆候があるかを確認する(確認専用)。

このツールは、**BIG-IP実機のbashシェル上で実行する**ことを前提にしている(他の多くの
scripts/*.pyと違い、外部からの能動スキャンではバージョン/ログを確認できないため)。
JPCERT-AT-2026-0028・F5 K000162605 が公式に挙げている侵害検出方法をそのまま自動化した
だけで、本ツール独自の判定ロジックは追加していない。

背景:
  - F5は2026-09-22、BIG-IP APMのOAuth UserInfoハンドラにおけるヒープベースのバッファ
    オーバーフロー(CVE-2026-94127)のアドバイザリを公表。APMがOAuth Authorization
    Serverとして構成され、仮想サーバーにAPM access policyとOAuth profileが設定されて
    いる場合、認証されていないリモートの攻撃者が任意のコードを実行する可能性がある。
    F5は本脆弱性が悪用されていると表明。CISA KEV掲載(2026-09-22、連邦機関の対応期限
    2026-09-25)。watchTowr Labsが詳細な攻撃手法を公表。
  - 影響バージョン: 21系(21.1.0)、17系(17.5.0〜17.5.1、17.1.0〜17.1.3)。
  - OAuth Client/Resource Serverとしてのみ使っている構成は対象外。

このツールが確認すること(JPCERT-AT-2026-0028「V. 侵害検出方法」をそのまま自動化):
  - `tmsh show sys version`(または--versionで指定した文字列)を影響範囲と照合。
  - `/var/log/apm`(既定パス、--apm-logで変更可)からログID「01990004」
    (OAuth UserInfo要求失敗)の件数を集計し、同一送信元IPからの反復が無いかを確認。
    ※ログの正確な行フォーマットは実機での裏取りができていないため、IPアドレスの
    抽出は「行内のIPv4らしき文字列」を拾うベストエフォートである旨に注意。
  - TMMコアファイル(既定 `/var/core/`、--core-dirで変更可)の有無を確認
    (TMMがループ状態に陥るとSODデーモンがSIGABRTを送信し生成されるとされる)。
  - `/etc/bigstart/scripts/tmm.finish`のSHA256ハッシュを算出して表示する
    (**既知の正常なハッシュとの比較は行わない** — バージョン・ビルドごとに正規の値が
    異なるため、本ツールが「これが正常値」と決め打ちすることはしない。運用者が自分の
    バックアップ/構成管理システムに記録した値と突き合わせること)。

安全のための制限:
  - **確認・集計・ハッシュ算出だけ**。設定変更、ファイルの書き換え、ネットワークへの
    送信は一切しない。
  - 実行するのは、このホストの `tmsh`・ログファイル・ファイルシステムの読み取りだけ。

使い方(BIG-IP実機のbashシェル上で):
    python3 scripts/f5_bigip_apm_check.py
    python3 scripts/f5_bigip_apm_check.py --out f5_apm.sarif
    python3 scripts/f5_bigip_apm_check.py --version 17.1.2 --apm-log /path/to/exported/apm.log

標準ライブラリだけで動く(Python 3.8 以上)。BIG-IP実機にPythonが無い場合は、
`/var/log/apm`(またはそのエクスポート)を他のLinuxホストへコピーし、--apm-logで
指定して実行することもできる(その場合、--versionでバージョンを別途指定すること)。
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "f5-bigip-apm-check"

DEFAULT_APM_LOG = "/var/log/apm"
DEFAULT_CORE_DIR = "/var/core"
DEFAULT_TMM_FINISH = "/etc/bigstart/scripts/tmm.finish"

LOG_ID = "01990004"
FAILURE_BURST_THRESHOLD = 10  # JPCERT-AT-2026-0028: 「10回以上」

VULNERABLE_VERSIONS = {
    (21, 1, 0),
    (17, 5, 0), (17, 5, 1),
    (17, 1, 0), (17, 1, 1), (17, 1, 2), (17, 1, 3),
}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")

REFERENCE = (
    "F5 K000162605 / JPCERT-AT-2026-0028 (CVE-2026-94127、CVSS 9.8、"
    "事前認証不要RCE、悪用確認済み、CISA KEV): "
    "https://my.f5.com/manage/s/article/K000162605"
)


def check_version(version_str: str | None) -> tuple[str, str]:
    if not version_str:
        try:
            out = subprocess.run(
                ["tmsh", "show", "sys", "version"], capture_output=True, text=True, timeout=10
            )
            version_str = (out.stdout or "") + (out.stderr or "")
        except FileNotFoundError:
            return "info", "tmsh が見つかりません(BIG-IP実機ではない、またはPATH外)。--version でバージョンを直接指定してください。"
        except Exception as e:
            return "medium", "tmsh の実行に失敗しました: %s" % e

    m = VERSION_RE.search(version_str)
    if not m:
        return "medium", "バージョン文字列を読み取れませんでした: %r" % version_str.strip()[:200]
    major, minor, patch = (int(x) for x in m.groups())
    if (major, minor, patch) in VULNERABLE_VERSIONS:
        return (
            "high",
            "BIG-IP APM %d.%d.%d は影響バージョンに該当します(21.1.0 / 17.5.0-17.5.1 / "
            "17.1.0-17.1.3)。F5のホットフィックス適用、または暫定のiRuleを検討してください。"
            % (major, minor, patch),
        )
    return "info", "BIG-IP APM %d.%d.%d は、公表されている影響バージョン一覧には該当しないように見えます。" % (major, minor, patch)


def check_apm_log(path: str) -> tuple[str, str]:
    if not os.path.isfile(path):
        return "info", "%s が見つかりません(--apm-log で場所を指定してください)。" % path
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [ln for ln in f if LOG_ID in ln]
    except OSError as e:
        return "medium", "%s の読み取りに失敗しました: %s" % (path, e)

    if not lines:
        return "info", "%s にログID %s(OAuth UserInfo要求失敗)は見つかりませんでした。" % (path, LOG_ID)

    per_ip = collections.Counter()
    unattributed = 0
    for ln in lines:
        ips = IPV4_RE.findall(ln)
        if ips:
            per_ip[ips[0]] += 1
        else:
            unattributed += 1

    worst_ip, worst_count = (per_ip.most_common(1)[0] if per_ip else (None, 0))
    total = len(lines)

    if worst_count >= FAILURE_BURST_THRESHOLD:
        return (
            "high",
            "ログID %s が合計%d件、うち送信元IP %s から%d件の反復が見つかりました"
            "(JPCERT-AT-2026-0028の目安「単一送信元から10回以上」に該当)。"
            "tmctl global_oauth_stat と /var/log/audit の該当時間帯を確認してください。"
            % (LOG_ID, total, worst_ip, worst_count),
        )
    return (
        "medium",
        "ログID %s が合計%d件見つかりましたが、単一送信元からの反復は閾値(%d件)未満です"
        "(IP抽出はベストエフォートのため、%d件は送信元IPを特定できませんでした)。"
        % (LOG_ID, total, FAILURE_BURST_THRESHOLD, unattributed),
    )


def check_core_files(core_dir: str) -> tuple[str, str]:
    if not os.path.isdir(core_dir):
        return "info", "%s が見つかりません(--core-dir で場所を指定してください)。" % core_dir
    matches = sorted(glob.glob(os.path.join(core_dir, "*tmm*core*")))
    if matches:
        return (
            "high",
            "%d件のTMMコアファイルが見つかりました: %s 。TMMループ(SODデーモンのSIGABRT)が"
            "発生した可能性があり、他の兆候とあわせて調査してください。"
            % (len(matches), ", ".join(os.path.basename(m) for m in matches[:5])),
        )
    return "info", "%s にTMMコアファイルは見つかりませんでした。" % core_dir


def check_tmm_finish(path: str) -> tuple[str, str]:
    if not os.path.isfile(path):
        return "info", "%s が見つかりません(--tmm-finish で場所を指定してください)。" % path
    try:
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
    except OSError as e:
        return "medium", "%s の読み取りに失敗しました: %s" % (path, e)
    return (
        "info",
        "%s のSHA256: %s 。バージョン/ビルドごとに正規の値が異なるため、本ツールは"
        "既知の正常値との比較は行いません。自分の構成管理・バックアップの記録と突き合わせること。"
        % (path, digest),
    )


def worst(*results: tuple[str, str]) -> str:
    order = {"high": 3, "medium": 2, "info": 1}
    return max(results, key=lambda r: order.get(r[0], 0))[0]


def to_sarif(checks: list[tuple[str, str, str]]) -> dict:
    level_map = {"high": "error", "medium": "warning", "info": "note"}
    results = []
    for check_id, severity, message in checks:
        results.append({
            "ruleId": "f5-bigip-apm-%s" % check_id,
            "level": level_map.get(severity, "warning"),
            "message": {"text": "%s %s" % (message, REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f5-bigip:%s" % check_id}}}],
            "properties": {"severityLabel": severity},
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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="", help="SARIFの出力先(省略時は標準出力に要約のみ表示)")
    ap.add_argument("--version", default="", help="tmshを使わず、バージョン文字列を直接指定する(例: 17.1.2)")
    ap.add_argument("--apm-log", default=DEFAULT_APM_LOG, help="apm ログのパス(既定: %s)" % DEFAULT_APM_LOG)
    ap.add_argument("--core-dir", default=DEFAULT_CORE_DIR, help="TMMコアファイルのディレクトリ(既定: %s)" % DEFAULT_CORE_DIR)
    ap.add_argument("--tmm-finish", default=DEFAULT_TMM_FINISH, help="tmm.finish のパス(既定: %s)" % DEFAULT_TMM_FINISH)
    args = ap.parse_args()

    checks = []
    sev, msg = check_version(args.version or None)
    checks.append(("version", sev, msg))
    sev, msg = check_apm_log(args.apm_log)
    checks.append(("apm-log", sev, msg))
    sev, msg = check_core_files(args.core_dir)
    checks.append(("core-files", sev, msg))
    sev, msg = check_tmm_finish(args.tmm_finish)
    checks.append(("tmm-finish", sev, msg))

    overall = worst(*[(sev, msg) for _, sev, msg in checks])
    print("総合: [%s]" % overall)
    print()
    for check_id, sev, msg in checks:
        print("[%s] (%s) %s" % (sev, check_id, msg))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(checks), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
