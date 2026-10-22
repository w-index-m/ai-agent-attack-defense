#!/usr/bin/env python3
"""java_cacerts_emudhra_check: ローカルの Java(OpenJDK/Oracle JDK)の cacerts(信頼ストア)に、
eMudhra の侵害されたCA(2026-10、CVE-2026-91403)に関連するルートCAが含まれているかを確認する(確認専用)。

背景:
  - 2026-10-17、eMudhraの中間CA証明書8件の秘密鍵が侵害されたことが実証付きで公開された
    (Mozilla Bugzilla #2083449。本リポジトリの R14 参照)。
  - OpenJDK/Oracle Javaのcacertsは、侵害された中間CAが連鎖するルートCA
    ("emSign ECC Root CA - G3" 等、および "AAA Certificate Services")を信頼済みのため、
    侵害された中間CAの鍵で署名された不正な証明書チェーンを検証してしまう恐れがある
    (CVE-2026-91403、CVSS 9.1、JSSEコンポーネント、Oracleが緊急Security Alertとして公開、
    IPAも2026-10-21に注意喚起)。Oracleの修正は、該当ルート自体ではなく、
    侵害された中間CAを個別に信頼しないようにするもの。

このツールが確認すること:
  - cacerts に、上記ルートCAに該当する(Owner に "emSign" または "AAA Certificate Services" を
    含む)エントリがあるか(`keytool -list -v` の出力を読むだけ)。
  - ローカルの `java -version` の出力(人が公式アドバイザリと突き合わせるための参考情報)。

**注意: ルートCAが信頼ストアにあること自体は「脆弱」の確定的な証拠ではない。**
Oracleの修正は該当ルートを不信任にするのではなく、侵害された中間CAだけを個別に
ブロックする方式のため、この確認だけではパッチ適用状況は判定できない。
最終判断は、Oracle公式のSecurity Alert(CVE-2026-91403)と、インストール済みJavaの
正確なバージョンで行うこと。

安全のための制限:
  - **確認だけ**。cacerts の変更、ネットワークへの接続は一切しない。
  - 実行するのは、このホストの keytool だけ。

使い方:
    python3 scripts/java_cacerts_emudhra_check.py
    python3 scripts/java_cacerts_emudhra_check.py --out java_cacerts_emudhra.sarif
    python3 scripts/java_cacerts_emudhra_check.py --storepass changeit  # 既定値と同じなら省略可

標準ライブラリだけで動く(Python 3.8 以上)。対象ホストに keytool(JDK付属)が必要。
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DRIVER = "java-cacerts-emudhra-check"

# R14で確認済みの、eMudhra侵害インシデントに連なるルートCAの名称(Owner DN に部分一致で探す)。
# 大文字小文字は問わない。
SUSPECT_ROOT_PATTERNS = [
    re.compile(r"emSign", re.I),
    re.compile(r"AAA Certificate Services", re.I),
]

CVE_REFERENCE = (
    "CVE-2026-91403 (CVSS 9.1, JSSE, Oracle Security Alert, 2026-10-21; IPA も同日注意喚起): "
    "OpenJDK/Oracle Java が、2026-10 に秘密鍵が侵害されたeMudhra中間CA証明書8件(本リポジトリの "
    "R14 参照)の連鎖するルートCAを信頼済みのため、侵害された中間CAで署名された不正な証明書を "
    "検証してしまう恐れがある。Oracle公式: https://www.oracle.com/security-alerts/alert-cve-2026-91403.html"
)

# IPA「Oracle Java の脆弱性対策について(2026年10月)」(2026-10-21公開)が「脆弱な版」として
# 列挙しているバージョン文字列(修正版ではない点に注意)。
# 出典: https://www.ipa.go.jp/security/security-alert/2026/1021-jre.html
IPA_LISTED_VULNERABLE_VERSIONS = [
    "27", "26.0.2", "25.0.4.1", "21.0.12.1", "17.0.20.1", "11.0.32.1", "8u503",
]


def extract_version_number(version_line: str) -> str | None:
    m = re.search(r'version\s+"([^"]+)"', version_line)
    return m.group(1) if m else None


def find_keytool() -> str | None:
    p = shutil.which("keytool")
    if p:
        return p
    return None


def java_version_string() -> str:
    java = shutil.which("java")
    if not java:
        return "(java コマンドが見つかりません)"
    try:
        r = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        return "(java -version の実行に失敗: %s)" % e
    # java -version は stderr に出力する実装が多い。環境によっては先頭に
    # "Picked up JAVA_TOOL_OPTIONS: ..." 等の雑音行が混ざるため、
    # "... version "..."" を含む行を優先的に拾う。
    out = (r.stderr or r.stdout).strip()
    if not out:
        return "(バージョン文字列を取得できませんでした)"
    for line in out.splitlines():
        if re.search(r'\bversion\s+"', line):
            return line.strip()
    return out.splitlines()[0]


def list_cacerts_entries(keytool: str, storepass: str) -> tuple[list[dict], str | None]:
    """keytool -list -v -cacerts の出力をパースし、[{alias, owner}] を返す。(entries, error)。"""
    try:
        r = subprocess.run(
            [keytool, "-list", "-v", "-cacerts", "-storepass", storepass],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], "keytool の実行に失敗しました: %s" % e
    if r.returncode != 0:
        # keytool の実際のエラー(例: パスワード誤り)は環境によって stdout に出ることがあり、
        # stderr には "Picked up JAVA_TOOL_OPTIONS: ..." のような雑音だけのこともあるため、
        # 両方を結合してから判定する。
        detail = "\n".join(x for x in (r.stderr, r.stdout) if x).strip()
        if "password was incorrect" in detail.lower() or "keystore password" in detail.lower():
            return [], "cacerts のパスワードが違います。--storepass で指定してください(既定: changeit)。"
        return [], "keytool の実行に失敗しました: %s" % detail

    entries = []
    alias = None
    for line in r.stdout.splitlines():
        m = re.match(r"^Alias name:\s*(.+)$", line.strip())
        if m:
            alias = m.group(1)
            continue
        m = re.match(r"^Owner:\s*(.+)$", line.strip())
        if m and alias:
            entries.append({"alias": alias, "owner": m.group(1)})
            alias = None
    return entries, None


def find_suspect_roots(entries: list[dict]) -> list[dict]:
    hits = []
    for e in entries:
        if any(p.search(e["owner"]) for p in SUSPECT_ROOT_PATTERNS):
            hits.append(e)
    return hits


def to_sarif(hits: list[dict], java_ver: str, host: str) -> dict:
    results = []
    for h in hits:
        results.append({
            "ruleId": "java-cacerts-emudhra-related-root",
            "level": "warning",
            "message": {"text": "cacerts に eMudhra侵害インシデント関連のルートCAが見つかりました: alias=%s owner=%s. %s"
                                 % (h["alias"], h["owner"], CVE_REFERENCE)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "java:cacerts"}}}],
            "properties": {"alias": h["alias"], "owner": h["owner"], "javaVersion": java_ver, "host": host},
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
    ap.add_argument("--storepass", default="changeit", help="cacerts のパスワード(既定: changeit、JDK標準の既定値)")
    ap.add_argument("--out", default="", help="SARIF の出力先(省略時は標準出力に要約だけ表示)")
    args = ap.parse_args()

    keytool = find_keytool()
    if not keytool:
        print("keytool が見つかりません。JDK がインストールされたホストで実行してください。", file=sys.stderr)
        return 2

    java_ver = java_version_string()
    entries, err = list_cacerts_entries(keytool, args.storepass)
    if err:
        print("エラー: " + err, file=sys.stderr)
        return 2

    hits = find_suspect_roots(entries)

    print("Java: %s" % java_ver)
    version_number = extract_version_number(java_ver)
    if version_number and version_number in IPA_LISTED_VULNERABLE_VERSIONS:
        print("  警告: このバージョン(%s)は、IPAが2026-10-21に「脆弱な版」として列挙した"
              "リストに一致します(修正版ではない)。Oracle公式アドバイザリで修正版への更新を確認すること。"
              % version_number)
    elif version_number:
        print("  (IPAの「脆弱な版」一覧には一致なし。ただし一覧は固定のバージョン文字列のみを列挙しており、"
              "これより古い版が安全という意味ではない。Oracle公式アドバイザリで必ず確認すること。)")
    print("cacerts のエントリ数: %d" % len(entries))
    if not hits:
        print("eMudhra侵害インシデント関連のルートCA(emSign / AAA Certificate Services)は"
              "見つかりませんでした。")
    else:
        print("%d 件、関連するルートCAが見つかりました:" % len(hits))
        for h in hits:
            print("  alias=%s" % h["alias"])
            print("    owner=%s" % h["owner"])
        print()
        print("注意: ルートCAの存在だけでは「脆弱」の確証にはならない(Oracleの修正は侵害された")
        print("中間CAだけを個別にブロックする方式)。上記のJavaバージョンを、Oracle公式の")
        print("Security Alert(CVE-2026-91403)の対象/修正バージョン一覧と突き合わせて判断すること。")
        print(CVE_REFERENCE)

    if args.out:
        host = platform.node() or "unknown-host"
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(to_sarif(hits, java_ver, host), f, ensure_ascii=False, indent=2)
        print()
        print("%s を書き出しました。" % args.out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
