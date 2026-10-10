# OS 更新の確認（RHEL / Windows）→ vuln_triage で優先度づけ

English summary: at the end of this file.

OS の更新状態を確認し、結果を SARIF 2.1.0 に書き出す。書き出したファイルは `vuln_triage.html` にそのまま読み込める。
**Linux（RHEL 系）と Windows で、別々のスクリプトに分けている。** 片方の環境の依存（PowerShell、Windows Update API、dnf）を、もう片方に持ち込まないため。

> ⚠️ 方針：**確認専用**。更新の適用、設定の変更、ネットワークへの送信は一切しない。
> 実行するのは、そのホストで動くコマンドだけ（リモートには接続しない）。**自分が管理する機器でだけ実行する。**

## できること

| スクリプト | 確認するもの | 使うコマンド | 出力 |
|---|---|---|---|
| `os_patch_check_linux.py` | **未適用**のセキュリティ更新（RHSA） | `dnf updateinfo list security --available` | 重大度つきの指摘（緊急〜低） |
| `os_patch_check_windows.py` | **適用済み**の更新（HotFix） | `Get-HotFix` | 情報（note）として記録 |
| `os_patch_check_windows.py --windows-pending` | **未適用**の更新（KB と MSRC 重大度） | Windows Update API（COM） | 重大度つきの指摘 |

Windows の未適用の確認は、Windows Update API を使うため、**管理者権限が要ることがあります**。

> 普通の利用者として `Get-HotFix`（HotFix の一覧）を実行するだけなら、読み取りだけで、管理者権限は通常いりません。

## 使い方

```bash
# Linux（RHEL / Rocky / AlmaLinux など、dnf のある機器で）
python3 scripts/os_patch_check_linux.py --out os_patch_linux.sarif
```

```powershell
# Windows（PowerShell / コマンドプロンプトで。適用済みの更新＝HotFix の一覧）
python scripts/os_patch_check_windows.py --out os_patch_windows.sarif

# Windows（未適用の更新も確認。時間がかかることがある。管理者で実行すると取れることがある）
python scripts/os_patch_check_windows.py --windows-pending --out os_patch_windows.sarif
```

Windows 版は Windows 以外で実行すると、その旨を出して止まります。Linux 版は dnf が無いと、その旨を出して止まります。

そのあと、`os_patch.sarif` を `vuln_triage.html` に読み込めば、優先度順に並びます。

## 検証

- RHEL：`dnf` の出力形式を模したスタブで、未適用の更新を重大度つきで SARIF に変換できることを確認。
- Windows：PowerShell の出力を模したスタブで、HotFix（適用済み）と、未適用（Windows Update API）の両方を確認。単一オブジェクトの JSON や、空の出力も正しく扱えた。
- 必要なコマンドが無い環境では、**クラッシュせず、わかりやすいエラーで終わる**ことを確認。
- 生成した SARIF を `vuln_triage.html` にヘッドレスブラウザで読み込み、一覧に更新の名前（RHSA 番号、パッケージ名、KB 番号）が出ることを確認。

**正直な限界**
- **実機（本物の dnf や Windows）では、まだ実行していません。** 検証は、コマンドの出力形式を模したスタブで行いました。実際の出力と細部が違う可能性があります。
- Windows Update API の結果は、環境（Windows のバージョン、管理者権限、WSUS の有無）で変わります。
- 「未適用」の一覧は、**その時点の機器が見ている更新源**に基づきます。更新源（リポジトリ）の設定によっては、本当の最新と差が出ることがあります。
- 脆弱性の**悪用可否**までは判定しません。重大度は、ベンダが付けたものをそのまま使っています。

> 確認・検知・優先度づけの設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。

---

## English summary

Two scripts check OS update status on **a machine you manage** and write SARIF 2.1.0 that `vuln_triage.html` can load:
`scripts/os_patch_check_linux.py` (RHEL pending security advisories via `dnf updateinfo`) and
`scripts/os_patch_check_windows.py` (installed HotFixes via `Get-HotFix`, recorded as informational; optionally pending
updates via the Windows Update API). They are split so each platform's dependencies stay out of the other. It is
check-only — it never applies updates, changes settings, or sends data off the host. Verified with stubs that mimic
the tool output, plus a headless load of the generated SARIF into the triage page. **Not yet run on real RHEL or
Windows hosts** — output details may differ in practice.
