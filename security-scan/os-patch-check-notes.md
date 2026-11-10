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

### RHEL 系：実機での検証（2026-10-31）

Docker Desktop（Windows、WSL2 バックエンド）上で、2つの dnf 系ディストロの素のコンテナに対して実行した。

- **`registry.access.redhat.com/ubi9/ubi`（Red Hat 公式 UBI）**: `dnf check-update` では約140件の更新が確認できる環境でも、`dnf updateinfo list security`（本スクリプトが使うコマンド）は**常に0件**を返した。原因を切り分けたところ、**UBIの無料リポジトリ（`ubi-9-baseos-rpms` 等）には、そもそもセキュリティ分類のメタデータ（updateinfo.xml、エラータ情報）が含まれていない**ことが判明。これはスクリプトの不具合ではなく、UBIが無料で提供する範囲の制約であり、本物のサブスクリプション登録済みRHELでしか得られない情報。
- **`rockylinux/rockylinux:9`（無料・登録不要、RHEL互換でエラータを公開配布）**: `dnf updateinfo list security`が実際に73件の`RLSA-`アドバイザリ（Critical〜Low）を返し、本スクリプト(`os_patch_check_linux.py`)も**同じ73件**を正しく検出した（生出力の件数とスクリプトの出力件数が一致）。これにより、本スクリプトのパース・重大度判定ロジックは、本物のセキュリティアドバイザリメタデータに対して正しく動くことを実機で確認できた。

### Windows系：実機での検証（2026-11-10）

利用者自身の実際のWindows PCで、`python3 scripts/os_patch_check_windows.py --out os_patch_windows.sarif`
を実行(既定、`--windows-pending`無し)。本物のPowerShell(`Get-HotFix`)から7件の適用済み
HotFixを正しく取得し、SARIFへの書き出しに成功した(未適用0件、`--windows-pending`未指定の
ため予期した結果)。これにより、スタブだけだったWindows側のHotFix取得・パース・SARIF変換の
一連の流れが、本物のPowerShell出力に対して正しく動くことを実機で確認できた。
生成した`os_patch_windows.sarif`を、実際のブラウザ(利用者自身のWindows PC)で
`vuln_triage.html`に「ファイルを選ぶ」経由で読み込んだところ、7件すべてが正しく取り込まれ、
重大度別件数(低: 7件)・KB番号を含む一覧(例: `KB5127694`)として表示されることを確認した。
これにより、`vuln_triage.html`側のSARIF取り込み・表示も、ヘッドレスブラウザではなく実際の
ブラウザ・実際のファイルで確認できた。

**正直な限界**
- `--windows-pending`(Windows Update API経由の未適用更新一覧)は、まだ実機で未確認。
- 本物のサブスクリプション登録済みRHEL（Rocky/AlmaLinuxではなく）での確認はまだ行っていない。Rocky/AlmaLinuxはRHELのエラータをそのまま再配布しているため、内容面では同等と考えられるが、完全な同一性は未確認。
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
