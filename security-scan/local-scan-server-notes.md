# ローカルスキャナー呼び出し（`scripts/local_scan_server.py`）

English summary: see the bottom of this file.

`vuln_triage.html`の「1. 診断結果を取り込む」は、これまで他で生成したJSONを貼り付ける/ファイルを選ぶ
だけだった。これに、**このリポジトリ自身**を対象に、既存の診断ツール(Semgrep・Trivy・gitleaks・
netcheck・zgrab2)をブラウザから直接呼び出すボタンを追加した。

仕組みは、既存の「5. 自前LLMに質問する」機能（ブラウザから`http://localhost:11434`に直接fetchする）
と同じパターン。`vuln_triage.html`自体は静的なページ(バックエンドを持たない)なので、ローカルで
`python3 scripts/local_scan_server.py`という小さな補助サーバーを自分で起動し、ページのJSがそこに
POSTする。

> ⚠️ 方針：確認専用。対象は**このリポジトリ自身の作業ツリーに固定**（リクエストで外部のパスを
> 指定することはできない。スクリプト自身の場所からリポジトリルートを解決する）。127.0.0.1だけで
> 待ち受け、ローカル開発用のツールとして作っている。外部に公開しないこと。

## エンドポイント

| パス | 実行する内容 | 備考 |
|---|---|---|
| `GET /health` | 疎通確認 | |
| `POST /scan/semgrep` | `semgrep scan --config p/default --exclude security-scan/sqli-lab/vulnerable_app.py --json`（CIの`.github/workflows/security-scan.yml`と同じコマンド） | ローカルに`semgrep`があればそれを優先、無ければDocker |
| `POST /scan/trivy` | `trivy fs --scanners vuln,misconfig,secret --format json .`（CIと同じ） | ローカルに`trivy`があればそれを優先、無ければDocker |
| `POST /scan/gitleaks` | `gitleaks detect --report-format=json --exit-code=0`（CIと同じ） | ローカルに`gitleaks`があればそれを優先、無ければDocker |
| `POST /scan/netcheck` | `netcheck/netcheck.py`の設定・許可範囲判定・スキャンロジックをそのまま再利用（サーバーは別途立てず、同期的にジョブを実行） | 対象は既定で`127.0.0.1`。リクエストで変えられるが、netcheck自身の許可範囲（`netcheck/config.json`）を超えることはできない |
| `POST /scan/zgrab2` | `scripts/zgrab2_guard.py`と同じ許可範囲判定を通した後、`zgrab2`本体を実行 | ボディに`i_own_these: true`が無いと一切実行しない。`zgrab2`本体が未インストールなら、その旨を明確なエラーで返す |

どのツールも、生のJSON出力をそのまま返す（加工しない）。ページ側は、既存の`addJson()`（貼り付け/
ファイル読み込みと同じ関数）にそのまま渡すので、解析ロジックは一本化されている。

## 使い方

```bash
python3 scripts/local_scan_server.py            # 既定ポート 8766
python3 scripts/local_scan_server.py --port 9000
```

ブラウザで`vuln_triage.html`を開き、「1. 診断結果を取り込む」の「ローカルスキャナーを呼び出す」から
各ボタンを押す。エンドポイントURL(既定`http://localhost:8766`)はこの端末のlocalStorageに保存される。

zgrab2だけ、対象(IP/CIDR/ホスト名)の入力と、「自社が管理している、または書面で許可を得た対象」
というチェックボックスの明示が必要。

## 検証の状態（正直に）

### サンドボックス内での検証

- **netcheckエンドポイント**: このリポジトリのサンドボックス内で、実際にサーバーを起動し、実際の
  ブラウザ(Playwright/Chromium)で`vuln_triage.html`を開いて「netcheckを実行」ボタンを押すところまで
  実機確認した。`127.0.0.1`に対して正しくスキャンが走り（開いているポート0件）、結果がトリアージ
  一覧に正しく取り込まれ、ブラウザのコンソールエラーも無いことを確認した。
- **CORS・consentゲート**: `curl`で`/health`・OPTIONSプリフライト・zgrab2の同意なし拒否・
  zgrab2本体未インストール時の明確なエラー、を個別に確認した。
- **semgrepエンドポイント**: このサンドボックスにインストールされているsemgrepは、依存パッケージの
  競合（`opentelemetry`関連のImportError）で壊れており、実行自体ができなかった。このおかげで
  「ツールが失敗したときにスタックトレースではなく明確なJSONエラーを返す」というエラーハンドリング
  経路は実際に確認できた。
- **trivy・gitleaksエンドポイント**: このサンドボックスにはDockerデーモンが無く（`docker info`が
  失敗する）、`trivy`・`gitleaks`バイナリも入っていないため、実行自体を試せなかった。

### 実機(Windows PC、Docker Desktop)での検証(2026-10-31)

ユーザー自身のWindows PCで、`python3 scripts/local_scan_server.py`を起動し、`vuln_triage.html`から
全ボタンを実際に押して確認した。

- **Semgrepエンドポイント**: ✅ 実行成功。11件の指摘を取り込み、「2. 全体像」に正しく反映された。
- **gitleaksエンドポイント**: ✅ 実行成功。結果が正しく取り込まれた。
- **netcheckエンドポイント**: ✅ 実行成功。実際に`127.0.0.1`上で3件の本物の露出(Ollama API
  11434番ポート・SMB 445番ポート・ポート80のバナー情報)を検出。対象入力欄(LAN内の他端末も指定可能)
  も実機確認済み。
- **zgrab2エンドポイント**: ✅ 設計どおり、本体未インストールの明確なエラーを確認(実機でも未インストール)。
- **Trivyエンドポイント**: 未確認(ボタンは押せる状態だが、結果の報告は無し)。

### この過程で実機から見つかり、修正したバグ

いずれも「動いているように見えるが、実は正しく動いていない」種類の不具合で、サンドボックスの
Playwright確認だけでは気づけなかった。実機でのクリック操作によって初めて見つかった。

1. **二重クリックで2つのスキャンが並行実行される**: ボタンに無効化処理が無く、連打すると同じ結果が
   二重に取り込まれる可能性があった。実行中は全ボタンを無効化するよう修正。
2. **「2. 全体像」が更新されない**: ローカルスキャナー経由の取り込みが`renderAll()`を呼んでおらず、
   内部データには追加されていても画面上の集計に一切反映されていなかった。
3. **`addJson()`の戻り値の意味を取り違え**: 空文字=成功・文字列あり=失敗/スキップ、という契約なのに
   常に✅成功として表示していた。
4. **分類ロジックがファイルパスも判定材料にしていた**: `security-scan/sqli-lab/`というフォルダ名の
   "sqli"という部分文字列だけで、無関係な指摘(`avoid-pickle`)がSQLインジェクション判定にマッチして
   いた。ファイルパスを分類対象から除外して修正。

Trivy以外はすべて実機で正常動作を確認済み。Trivyのみ、お手元での確認がまだ無い。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。

---

## English summary

Adds `scripts/local_scan_server.py`, a small localhost-only companion HTTP server that lets
`vuln_triage.html` (a static, backend-less page) trigger Semgrep, Trivy, gitleaks, netcheck and
zgrab2 directly from the browser — the same pattern the page's existing "ask your own LLM" panel
already uses against a local Ollama instance. Scope is fixed to this repository's own working tree
(no arbitrary path from the request). Semgrep/Trivy/gitleaks mirror the exact commands used in
`.github/workflows/security-scan.yml`. netcheck reuses `netcheck/netcheck.py`'s own config and
allowed-range logic unchanged. zgrab2 requires an explicit `i_own_these: true` consent flag and is
routed through the same allow-range filtering as `scripts/zgrab2_guard.py`, and returns a clear
error if the `zgrab2` binary isn't installed rather than silently no-op'ing.

Verified in this sandbox: the netcheck endpoint end-to-end, via a real headless-browser click on
`vuln_triage.html` against a live server (correct scan, correct ingestion, no console errors); CORS
preflight; the zgrab2 consent gate and its missing-binary error path. Not verified in this sandbox:
Semgrep's success path (the sandbox's own semgrep install is broken, which did let us confirm the
error-handling path instead), and Trivy/gitleaks/zgrab2's actual execution (no Docker daemon, no
local binaries available here).

### Real-machine verification (Windows PC with Docker Desktop, 2026-10-31)

The user ran every button against their own machine. Semgrep (✅, 11 real findings, correctly
reflected in the overview), gitleaks (✅), netcheck (✅, found 3 genuine exposures on their own
`127.0.0.1`: an open Ollama API on 11434, SMB on 445, and a version banner on port 80; the new
per-request target field for scanning other LAN hosts was also exercised), and zgrab2 (✅, correctly
reported the binary as not installed, same as this sandbox). Trivy's button exists but no result was
reported back.

This real-machine testing surfaced four genuine bugs no sandbox Playwright run had caught, since
each one only shows up when a human actually clicks through the flow twice or reads the resulting
numbers critically: double-clicking a scan button could run two scans concurrently and double-count
results (fixed: buttons disable while a scan is in flight); the local-scan ingestion path never
called `renderAll()`, so the overview counts silently never updated even on a successful import
(fixed); `addJson()`'s return value was read backwards, showing a skip/error message with a ✅ as if
it were success (fixed); and the classifier matched category keywords against the full file path,
so a file under `security-scan/sqli-lab/` was mislabeled as a SQL-injection finding purely because
of the substring "sqli" in the folder name (fixed by classifying on rule ID / title / detail only,
not the path).
