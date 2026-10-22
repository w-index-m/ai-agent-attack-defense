#!/usr/bin/env python3
"""linux_kernel_infinitycore_check: 実行中のLinuxカーネルが、「Infinity Core」(2026-10-16公開、
研究者 Hyunwoo Kim / V4bel)として報告された6件のローカル権限昇格(LPE)脆弱性の対象になりうるかを
確認する(確認専用)。

背景:
  - 2026-10-16、ディストリビューション向けエンバーゴ終了後に公開。timer・signal・memory・futex・
    scheduler・SLUB/SLABの6箇所のカーネルバグで、5件がroot権限昇格に使える(公開PoCあり:
    GitHub V4bel/InfinityCore)。
  - 主要: CVE-2026-98260(exec()内のtimer use-after-free、CVSS 7.8)
  - 他: CVE-2026-98256(signal)、CVE-2026-89754(メモリ管理)、CVE-2026-80775(futex)、
    CVE-2026-98385(scheduler、特定構成でroot+コンテナエスケープ)、
    CVE-2026-97941(SLUB/SLAB、クラッシュのみ・root到達のPoCは未公開)
  - 回避策(sysctl等)は無く、カーネル更新+再起動のみが対処。
  - ディストリビューションごとにバックポートされたカーネルバージョン表記がバラバラなため、
    **このツールは単純な数値比較で「脆弱/安全」を断定しない**(CloudLinux CL9のような、
    一次情報で正確な修正済みビルド番号が分かっている場合を除く)。それ以外は、実行中の
    カーネルバージョン・ディストリビューション情報を表示し、該当ディストリビューションの
    公式セキュリティアドバイザリでの確認を促す。

このツールが確認すること:
  - `uname -r`(カーネルリリース文字列)
  - `/etc/os-release`(ディストリビューションとバージョン)
  - CloudLinux CL9の場合のみ、既知の修正済みビルド(5.14.0-687.59.1.el9_8)との比較

安全のための制限:
  - **確認だけ**。カーネルの更新、設定変更、ネットワークへの接続は一切しない。
  - 実行するのは、このホストの `uname`/`/etc/os-release` の読み取りだけ。

使い方:
    python3 scripts/linux_kernel_infinitycore_check.py
    python3 scripts/linux_kernel_infinitycore_check.py --out infinitycore.sarif

標準ライブラリだけで動く(Python 3.8 以上)。
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "linux-kernel-infinitycore-check"

CVES = [
    ("CVE-2026-98260", "timer (exec() 内の use-after-free)", "CVSS 7.8、root権限昇格の公開PoCあり"),
    ("CVE-2026-98256", "signal", "root権限昇格の公開PoCあり"),
    ("CVE-2026-89754", "メモリ管理", "root権限昇格の公開PoCあり"),
    ("CVE-2026-80775", "futex", "root権限昇格の公開PoCあり"),
    ("CVE-2026-98385", "scheduler", "特定構成でroot権限昇格+コンテナエスケープの公開PoCあり"),
    ("CVE-2026-97941", "SLUB/SLAB", "クラッシュのみ確認。root到達の公開PoCは無し(2026-10-22時点)"),
]

REFERENCE = (
    "Infinity Core(Hyunwoo Kim / V4bel、2026-10-16公開、ディストリビューション向けエンバーゴ終了後): "
    "https://github.com/V4bel/InfinityCore — 回避策(sysctl等)は無く、カーネル更新+再起動のみが対処。"
)

# CloudLinuxのみ、一次情報(CloudLinux公式ブログ)で正確な修正済みビルドが判明しているため、
# このディストリビューションだけは具体的な比較を行う。他は版表記がディストリビューションごとに
# バラバラ(バックポート)なため、断定を避ける。
CLOUDLINUX_CL9_FIXED_BUILD = "5.14.0-687.59.1.el9_8"


def kernel_release() -> str:
    return platform.release()


def read_os_release() -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                info[key] = value.strip('"')
    except OSError:
        pass
    return info


def assess(kernel: str, os_release: dict[str, str]) -> tuple[str, str]:
    """Return (severity, message) -- an informational assessment, not a hard verdict
    except for the one case (CloudLinux CL9) where a precise fixed build is known."""
    distro_id = os_release.get("ID", "").lower()
    is_cloudlinux_9 = distro_id == "cloudlinux" and os_release.get("VERSION_ID", "").startswith("9")

    if is_cloudlinux_9:
        if kernel == CLOUDLINUX_CL9_FIXED_BUILD:
            return "info", "CloudLinux CL9: 既知の修正済みビルド(%s)と一致しています。" % CLOUDLINUX_CL9_FIXED_BUILD
        return (
            "high",
            "CloudLinux CL9: 実行中のカーネル(%s)が、既知の修正済みビルド(%s)と一致しません。"
            "CloudLinux公式のアドバイザリで最新の修正状況を確認してください。"
            % (kernel, CLOUDLINUX_CL9_FIXED_BUILD),
        )

    distro_label = " ".join(x for x in (os_release.get("NAME", ""), os_release.get("VERSION", "")) if x) or "(不明)"
    return (
        "medium",
        "実行中のカーネル: %s / ディストリビューション: %s。"
        "このツールはディストリビューションごとのバックポート差異のため、バージョン番号からの"
        "自動判定を行いません。Ubuntu 26.04では公開PoCでroot到達を確認、Ubuntu 24.04/Debianでは"
        "(2026-10-19時点の報告で)クラッシュのみとされています。お使いのディストリビューションの"
        "公式セキュリティアドバイザリで、Infinity Core(CVE-2026-98260等)への対応状況を確認してください。"
        % (kernel, distro_label),
    )


def to_sarif(severity: str, message: str, kernel: str) -> dict:
    level = {"high": "error", "medium": "warning", "info": "note"}.get(severity, "warning")
    results = [{
        "ruleId": "linux-kernel-infinitycore",
        "level": level,
        "message": {"text": "%s %s" % (message, REFERENCE)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "linux:uname"}}}],
        "properties": {"severityLabel": severity, "kernelRelease": kernel},
    }]
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
    args = ap.parse_args()

    if sys.platform.startswith("win"):
        print("Windowsでは実行できません。対象はLinuxホストです。", file=sys.stderr)
        return 2

    kernel = kernel_release()
    os_release = read_os_release()
    severity, message = assess(kernel, os_release)

    print("カーネル: %s" % kernel)
    distro_label = " ".join(x for x in (os_release.get("NAME", ""), os_release.get("VERSION", "")) if x)
    print("ディストリビューション: %s" % (distro_label or "(不明、/etc/os-releaseが読めませんでした)"))
    print("-" * 60)
    print("[%s] %s" % (severity, message))
    print()
    print("対象のCVE一覧(Infinity Core):")
    for cve, subsystem, note in CVES:
        print("  %s (%s): %s" % (cve, subsystem, note))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(severity, message, kernel), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
