#!/usr/bin/env python3
"""linux_kernel_cve202698432_check: Linuxカーネルの、CVE-2026-98432(IPv4 TCPのSYN/SYNACK処理
における use-after-free、CVSS 3.1 9.8・Critical、Ubuntu優先度High)への該当状況を確認する
(確認専用)。

背景:
  - Ubuntuセキュリティページ(2026-10-15公開、2026-10-28更新)より: 再送されたSYNが別CPUで
    処理されると、既に子ソケットへ渡されて(kfree_rcuではなく)通常のkfree()で解放済みの
    IPオプション(ireq->ireq_opt)をSYNACK経路が参照してしまい、ip_options_build()内で
    use-after-freeが発生する。関連関数: tcp_v4_syn_recv_sock・tcp_v4_reqsk_destructor・
    inet_sock_destruct。
  - 類似の経路がリクエストソケットのマイグレーション機能(sysctl net.ipv4.tcp_migrate_req=1、
    またはBPF_SK_REUSEPORT_SELECT_OR_MIGRATEプログラム使用時)でも存在する。
  - IPv6は最初の問題の対象外。IPv6側のマイグレーション問題(CALISPOが設定するipv6_opt)は
    別パッチで対応予定、とされている。
  - **2026-10-28時点、Ubuntuの全サポート対象リリース(16.04〜26.10、linux-aws/azure/gcp等の
    派生カーネルも含む)で"Vulnerable (work in progress)"のままで、修正済みパッケージは
    1件も公開されていない。** したがってこのツールは(linux_kernel_infinitycore_check.pyの
    CloudLinux CL9のような)バージョン番号での確定判定を一切行わない — 修正版自体が
    まだ存在しないため。
  - トリガーは再送されたSYNパケットであり、ネットワーク到達可能な攻撃者が送信できる類の
    入力に見えるが、Ubuntuのページ自体にはリモート悪用可否・認証要否・実悪用の有無は
    明記されていない(本ツールもそれらを断定しない)。

このツールが確認すること:
  - `uname -r`(カーネルリリース文字列)・`/etc/os-release`(表示のみ、「修正済みかどうか」の
    判定はしない。2026-10-28時点で修正版が存在しないため)。
  - `sysctl net.ipv4.tcp_migrate_req`(読み取れる場合): マイグレーション機能が有効(`1`)なら、
    説明にある追加の悪用経路が構成として開いていることを示す参考情報として表示する。
  - ログ確認(任意、--dmesg / --log-path / --journalctl-kernel): カーネルログから、
    本CVEに関連しそうなKASAN/UAFクラッシュの痕跡(本CVEが影響する関数名の近傍での
    "slab-use-after-free"等)を探す。**これも最も弱い、参考程度のヒューリスティック**:
    (1) 成功した攻撃は必ずしもクラッシュを起こすとは限らない(KASANが有効な検証環境でのみ
    確実に検出できる)。(2) 対象関数名はTCP実装内の一般的な関数でもあるため、無関係な
    バグでも同じ近傍に出現しうる。ヒットの有無いずれも確証にはならない。

安全のための制限:
  - **確認だけ**。カーネルの更新、sysctlの変更、ネットワークへの接続は一切しない。
  - 実行するのは、このホストの `uname`/`/etc/os-release`/`sysctl`の読み取りだけ。

使い方:
    python3 scripts/linux_kernel_cve202698432_check.py
    python3 scripts/linux_kernel_cve202698432_check.py --out cve202698432.sarif
    python3 scripts/linux_kernel_cve202698432_check.py --dmesg
    python3 scripts/linux_kernel_cve202698432_check.py --log-path /path/to/saved_dmesg.txt
    python3 scripts/linux_kernel_cve202698432_check.py --journalctl-kernel

標準ライブラリだけで動く(Python 3.8 以上)。
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "linux-kernel-cve-2026-98432-check"

REFERENCE = (
    "CVE-2026-98432 (Ubuntu Security, 公開2026-10-15・最終更新2026-10-28時点): "
    "https://ubuntu.com/security/CVE-2026-98432 -- Ubuntu優先度High、CVSS 3.1 9.8(Critical)。"
    "全サポート対象リリースで修正版は未公開(Vulnerable, work in progress)。"
)

# ip_options_build()内のuse-after-freeに関連する関数名(KASANレポートの近傍に出現しうる)。
RELEVANT_FUNCTION_MARKERS = [
    "tcp_v4_syn_recv_sock",
    "tcp_v4_reqsk_destructor",
    "inet_sock_destruct",
    "ip_options_build",
]
# 一般的なKASAN/UAFクラッシュの兆候(これ単体では何の確証にもならない)。
UAF_CRASH_MARKERS = [
    "BUG: KASAN: slab-use-after-free",
    "BUG: KASAN:",
    "Kernel panic",
    "general protection fault",
    "Call Trace:",
]
LOG_CONTEXT_WINDOW = 8


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


def read_migrate_req_sysctl() -> str | None:
    """net.ipv4.tcp_migrate_req の値を読む(権限/非Linuxで読めなければNone)。"""
    try:
        with open("/proc/sys/net/ipv4/tcp_migrate_req", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        pass
    try:
        out = subprocess.run(
            ["sysctl", "-n", "net.ipv4.tcp_migrate_req"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return None


def read_kernel_log_lines(use_dmesg: bool, log_path: str, use_journalctl: bool) -> tuple[list[str], str | None]:
    if use_dmesg:
        try:
            out = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            return [], "dmesg コマンドが見つかりません。"
        except Exception as e:
            return [], "dmesg の実行に失敗しました: %s" % e
        if out.returncode != 0 and not out.stdout:
            detail = (out.stderr or "").strip()
            return [], "dmesg の実行に失敗しました(権限不足の可能性): %s" % detail[:200]
        return out.stdout.splitlines(), None

    if use_journalctl:
        try:
            out = subprocess.run(
                ["journalctl", "-k", "-n", "5000", "--no-pager"],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            return [], "journalctl コマンドが見つかりません。"
        except Exception as e:
            return [], "journalctl の実行に失敗しました: %s" % e
        if out.returncode != 0 and not out.stdout:
            return [], "journalctl -k の実行に失敗しました: %s" % (out.stderr or "").strip()[:200]
        return out.stdout.splitlines(), None

    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            return f.readlines(), None
    except OSError as e:
        return [], "%s の読み取りに失敗しました: %s" % (log_path, e)


def scan_kernel_log_for_crash(lines: list[str]) -> list[tuple[int, str]]:
    """UAF/KASANクラッシュの痕跡を、CVE-2026-98432に関連する関数名と近傍(前後数行)で探す。
    行単位の単純な文字列一致のみ(構文解析はしない)。"""
    hits = []
    n = len(lines)
    for i, ln in enumerate(lines):
        if not any(marker in ln for marker in UAF_CRASH_MARKERS):
            continue
        lo, hi = max(0, i - LOG_CONTEXT_WINDOW), min(n, i + LOG_CONTEXT_WINDOW + 1)
        window = "".join(lines[lo:hi])
        if any(marker in window for marker in RELEVANT_FUNCTION_MARKERS):
            hits.append((i + 1, ln.rstrip()))
    return hits


def to_sarif(kernel: str, migrate_req: str | None, log_hits: list[tuple[int, str]] | None = None) -> dict:
    results = [{
        "ruleId": "linux-kernel-cve-2026-98432",
        "level": "warning",
        "message": {
            "text": "実行中のカーネル: %s。2026-10-28時点、修正版は未公開のため、"
                    "このツールはバージョンでの合否判定を行わない。%s"
                    % (kernel, REFERENCE)
        },
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "linux:uname"}}}],
        "properties": {"severityLabel": "medium", "kernelRelease": kernel},
    }]
    if migrate_req is not None:
        level = "error" if migrate_req.strip() == "1" else "note"
        results.append({
            "ruleId": "linux-kernel-cve-2026-98432-migrate-req",
            "level": level,
            "message": {"text": "net.ipv4.tcp_migrate_req = %s。1の場合、本CVEで説明される"
                                 "追加の悪用経路(リクエストソケットのマイグレーション)が"
                                 "構成として開いている。%s" % (migrate_req, REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "linux:sysctl"}}}],
            "properties": {"severityLabel": "high" if migrate_req.strip() == "1" else "info"},
        })
    for lineno, text in (log_hits or []):
        results.append({
            "ruleId": "linux-kernel-cve-2026-98432-crash-lead",
            "level": "note",
            "message": {"text": "ログ%d行目: CVE-2026-98432関連関数の近傍でのUAF/KASANクラッシュ痕跡"
                                 "(参考情報、確証ではない): %s %s" % (lineno, text, REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "linux:dmesg"}, "region": {"startLine": lineno}}}],
            "properties": {"severityLabel": "medium"},
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
    ap.add_argument("--dmesg", action="store_true", help="任意: dmesgコマンドを実行してUAFクラッシュの痕跡を探す")
    ap.add_argument("--log-path", default="", help="任意: --dmesgの代わりに、保存済みのdmesg出力ファイルから探す")
    ap.add_argument("--journalctl-kernel", action="store_true", help="任意: --dmesgの代わりに、journalctl -k から探す")
    args = ap.parse_args()

    if sys.platform.startswith("win"):
        print("Windowsでは実行できません。対象はLinuxホストです。", file=sys.stderr)
        return 2

    kernel = kernel_release()
    os_release = read_os_release()
    migrate_req = read_migrate_req_sysctl()

    print("カーネル: %s" % kernel)
    distro_label = " ".join(x for x in (os_release.get("NAME", ""), os_release.get("VERSION", "")) if x)
    print("ディストリビューション: %s" % (distro_label or "(不明、/etc/os-releaseが読めませんでした)"))
    print("-" * 60)
    print("[medium] 2026-10-28時点、Ubuntuの全サポート対象リリースで修正版は未公開のため、")
    print("バージョン番号からの合否判定は行わない。公式アドバイザリで最新の修正状況を確認すること。")
    print(REFERENCE)
    print()
    if migrate_req is not None:
        flag = "有効(1) — 追加の悪用経路が構成として開いている" if migrate_req.strip() == "1" else "無効/既定(%s)" % migrate_req
        print("net.ipv4.tcp_migrate_req: %s" % flag)
    else:
        print("net.ipv4.tcp_migrate_req: 読み取れませんでした(権限不足、または非Linux)")

    log_hits: list[tuple[int, str]] = []
    if args.dmesg or args.log_path or args.journalctl_kernel:
        lines, log_err = read_kernel_log_lines(args.dmesg, args.log_path, args.journalctl_kernel)
        print()
        if log_err:
            print("ログ確認エラー: " + log_err, file=sys.stderr)
        else:
            source = "dmesg" if args.dmesg else ("journalctl -k" if args.journalctl_kernel else args.log_path)
            log_hits = scan_kernel_log_for_crash(lines)
            print("ログ確認(%s、%d行) — 参考情報・最も弱いヒューリスティック:" % (source, len(lines)))
            if log_hits:
                print("  CVE-2026-98432関連関数近傍でのUAF/KASANクラッシュ痕跡が%d件見つかりました:" % len(log_hits))
                for lineno, text in log_hits[:10]:
                    print("    行%d: %s" % (lineno, text))
                print("  注意: KASAN等の検証ビルドでなければ検出できない可能性が高く、見つからないことは")
                print("  「安全」の確証にはならない。対象関数名は一般的なTCP実装内の関数でもある。")
            else:
                print("  該当する痕跡は見つかりませんでした(見つからないことも「安全」の確証にはならない)。")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(kernel, migrate_req, log_hits), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
