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

- **netcheckエンドポイント**: このリポジトリのサンドボックス内で、実際にサーバーを起動し、実際の
  ブラウザ(Playwright/Chromium)で`vuln_triage.html`を開いて「netcheckを実行」ボタンを押すところまで
  実機確認した。`127.0.0.1`に対して正しくスキャンが走り（開いているポート0件）、結果がトリアージ
  一覧に正しく取り込まれ、ブラウザのコンソールエラーも無いことを確認した。
- **CORS・consentゲート**: `curl`で`/health`・OPTIONSプリフライト・zgrab2の同意なし拒否・
  zgrab2本体未インストール時の明確なエラー、を個別に確認した。
- **semgrepエンドポイント**: このサンドボックスにインストールされているsemgrepは、依存パッケージの
  競合（`opentelemetry`関連のImportError）で壊れており、実行自体ができなかった。このおかげで
  「ツールが失敗したときにスタックトレースではなく明確なJSONエラーを返す」というエラーハンドリング
  経路は実際に確認できたが、**正常系（実際にSemgrepが指摘を返すケース）は未確認**。
- **trivy・gitleaksエンドポイント**: このサンドボックスにはDockerデーモンが無く（`docker info`が
  失敗する）、`trivy`・`gitleaks`バイナリも入っていないため、**実行自体を試せていない**。CIの
  コマンドをそのまま転記しているのでロジックは正しいはずだが、未検証。
- **zgrab2エンドポイント**: 本リポジトリでzgrab2本体を使った実行は一度も無い（`zgrab2-notes.md`に
  既出）。今回も、許可範囲チェック・同意ゲートまでは確認できたが、`zgrab2`本体そのものの実行は
  未検証。

実際に使うには、Docker Desktop・各ツール・`zgrab2`本体を入れた環境(お手元のPC)での確認が必要。

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
local binaries available here). Full verification needs a machine with Docker and/or these tools
installed.
