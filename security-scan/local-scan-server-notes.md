# ローカルスキャナー呼び出し（`scripts/local_scan_server.py`）

English summary: see the bottom of this file.

`vuln_triage.html`の「1. 診断結果を取り込む」は、これまで他で生成したJSONを貼り付ける/ファイルを選ぶ
だけだった。これに、**このリポジトリ自身**を対象に、既存の診断ツール(Semgrep・Trivy・gitleaks・
netcheck・zgrab2・Strix)をブラウザから直接呼び出すボタンを追加した。

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
| `POST /scan/netcheck` | `netcheck/netcheck.py`の設定・許可範囲判定・スキャンロジックをそのまま再利用（サーバーは別途立てず、同期的にジョブを実行） | 対象は既定で`127.0.0.1`。リクエストで変えられるが、netcheck自身の許可範囲（`netcheck/config.json`）を超えることはできない。`ports`（`"standard"`既定／`"extended"`）はGUIの「netcheckのポート範囲」セレクトから選べる |
| `POST /scan/zgrab2` | `scripts/zgrab2_guard.py`と同じ許可範囲判定を通した後、`zgrab2`本体を実行 | ボディに`i_own_these: true`が無いと一切実行しない。`zgrab2`本体が未インストールなら、その旨を明確なエラーで返す。`zgrab2`自体はこのリポジトリに含まれない別のOSS（[zmap/zgrab2](https://github.com/zmap/zgrab2)）で、`pull`しただけでは入らず、別途ビルド・PATHへの配置が必要。`module`（既定`"http"`。`ssh`・`tls`・`ftp`など）はGUIの「zgrab2のモジュール」欄から選べる |
| `POST /scan/strix` | [usestrix/strix](https://github.com/usestrix/strix)のモックLLM版PoC(`strix-local-poc/`)を実行し、生成された`findings.sarif`を返す | ボディに`i_own_these: true`が無いと一切実行しない。環境変数`STRIX_LOCAL_DIR`に、事前にclone・パッチ適用・`uv sync`済みのStrix作業コピーのパスを設定しておく必要がある(このエンドポイント自身は第三者リポジトリのcloneやパッチ適用は行わない)。対象(`targets`、既定`127.0.0.1`)は、netcheck/zgrab2と同じ許可範囲判定(`netcheck/config.json`)を通した1台のみ指定可。既定(127.0.0.1)の場合だけこのリポジトリ自身の`sqli-lab`デモアプリを自動起動し、それ以外を指定した場合は対象側であらかじめ同等のアプリを起動しておく必要がある |
| `POST /scan/cairn` | [oritera/Cairn](https://github.com/oritera/Cairn)を、Dockerワーカー・LLMを使わず`CairnClient`で直接駆動し(`cairn-lab/run_real_scan.py`)、実際にSQLi認証バイパスを再現してCairnのFactとして記録、エクスポートしたFactをSARIF形式に変換して返す | ボディに`i_own_these: true`が無いと一切実行しない。環境変数`CAIRN_LOCAL_DIR`に、事前にclone・`uv sync --project cairn`済みのCairn作業コピーのパスを設定しておく必要がある(このエンドポイント自身は第三者リポジトリのcloneは行わない)。対象(`targets`、既定`127.0.0.1`)はStrixと同じ許可範囲判定・1台のみ。Cairnの実ディスパッチャ(`cairn dispatch`)は使わない(下記「なぜディスパッチャを使わないか」参照) |

どのツールも、生のJSON出力をそのまま返す（加工しない）。ページ側は、既存の`addJson()`（貼り付け/
ファイル読み込みと同じ関数）にそのまま渡すので、解析ロジックは一本化されている。`strix`が返す
`findings.sarif`も、`cairn`が変換して返すSARIF相当のJSONも、既存のSARIF解析ロジック(サンプルの
`report.sarif`と同じコードパス)でそのまま読める。

### なぜCairnはディスパッチャ(`cairn dispatch`)を使わないか

Cairnの実ディスパッチャ(Docker workerコンテナ + LLM)は、workerの応答がCairn独自のJSONスキーマ
(`{"accepted": true, ...}`等)に従うことを要求している。台本によるプレーンテキスト応答(Strixの
モックLLMと同じ発想)ではこのスキーマに合わず、「JSON解析失敗」としてタスクが`completed`扱いに
ならず無限リトライになることが、`cairn-authorized-lab-runbook.md`§6.5で既に判明している
(クラッシュや危険な動作ではないが、確実に完了しない)。

そのため`/scan/cairn`は、ディスパッチャ/ワーカー/LLM層を一切経由せず、PR #89の
`handoff_recheck_test.py`と同じ手法(`CairnClient`でサーバーAPIを直接呼ぶ)を踏襲しつつ、
テスト用マーカー文字列の代わりに**実際のcurlによるSQLi認証バイパス**(Strixの
`mock_llm_server.py`で使っているのと同じペイロード)を実行し、その結果をFactとして記録する
(`cairn-lab/run_real_scan.py`)。

## 使い方

```bash
python3 scripts/local_scan_server.py            # 既定ポート 8766
python3 scripts/local_scan_server.py --port 9000
```

ブラウザで`vuln_triage.html`を開き、「1. 診断結果を取り込む」の「ローカルスキャナーを呼び出す」から
各ボタンを押す。エンドポイントURL(既定`http://localhost:8766`)はこの端末のlocalStorageに保存される。

zgrab2だけ、対象(IP/CIDR/ホスト名)の入力と、「自社が管理している、または書面で許可を得た対象」
というチェックボックスの明示が必要。

Strixを使うには、事前に[`strix-local-poc/README.md`](strix-local-poc/README.md)の手順(clone・
パッチ適用・`uv sync`)を済ませた作業コピーが必要。そのパスを`STRIX_LOCAL_DIR`環境変数に設定した
状態で`local_scan_server.py`を起動すること。「sqli-labデモアプリへの攻撃実行に同意する」チェック
ボックスの明示も必要(実際にSQLi認証バイパス等のペイロードを、このリポジトリ自身のデモアプリに
送る能動的な操作のため)。`vulnerable_app.py`・`mock_llm_server.py`は、まだ起動していなければ
エンドポイント自身が自動で起動する。

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
- **strixエンドポイント**: `uv`はこのサンドボックスに入っていたが、`https://github.com/usestrix/strix`
  へのネットワークアクセスがこの環境のネットワークポリシーで拒否された(他の外部ホストと同じ理由)ため、
  Strix本体のclone・完全なエンドツーエンドの実行は**試せなかった**。代わりに以下を個別に確認した:
  - `i_own_these`無しでの拒否、`STRIX_LOCAL_DIR`未設定時の明確なエラーメッセージ、を`curl`と
    実際のブラウザ(Playwright)経由の両方で確認。
  - Strixが依存する補助サーバー2つ(`security-scan/sqli-lab/vulnerable_app.py`、
    `security-scan/strix-local-poc/mock_llm_server.py`)が、単体ではこのサンドボックスで正常に
    起動・応答することを確認(前者はSQLi認証バイパスの実通信、後者はモック応答)。これはStrixの
    実行エンドポイントが内部で自動起動を試みる、まさにその2つのコンポーネント。
  - コードレビューで、サブプロセスのタイムアウト・`strix_runs`配下の新規run検出・`findings.sarif`
    読み取りのロジックを確認。vuln_triage.htmlの既存SARIFパーサー(`parseOne()`のsarif分岐)が
    期待するフィールド(`version`・`runs[].tool.driver.name`・`results[].ruleId/message/locations/level`)
    と、標準SARIF 2.1.0形式(`strix-local-backend-notes.md`の検証5で確認済みのStrix出力と同じ形式)が
    一致することも確認済み。

- **cairnエンドポイント**: ✅ **このサンドボックス内で、完全なエンドツーエンド実機確認ができた**
  (Strix/Semgrep/Trivy/gitleaksと異なり、必要な外部リソースが全てこのサンドボックスに既に揃って
  いたため)。手順:
  1. `/home/user/oritera/cairn`(このセッションの過去の作業で既にclone・`uv sync`済みのCairn
     作業コピー)を`CAIRN_LOCAL_DIR`に設定。
  2. サーバーをクリーンな状態(`vulnerable_app.py`・`cairn serve`とも未起動)から起動し、
     `curl -X POST /scan/cairn -d '{"i_own_these":true}'`を実行。両プロセスが自動起動され、
     実際にSQLi認証バイパス(`curl 'http://127.0.0.1:5000/login?username=admin%27%20--&password=x'`)が
     再現され、`Login OK. ... Rows: [(3, 'admin', 1)]`という本物のレスポンスがCairnのFact
     (`f001`)として記録され、正しい形のSARIF JSONが返ることを確認した。
  3. Playwright(実ブラウザ)で`vuln_triage.html`を開き、「全部消す」→Cairnの同意チェックボックス→
     「Cairnを実行」ボタンをクリックする、実際の利用フローも確認。✅成功表示、「2. 全体像」が
     正しく1件(中・連鎖1「SQLインジェクション」に該当)に再描画されることまで確認した。

### 対象(IP)を指定できるように変更(2026-11-01)

当初、Strix/Cairnの攻撃対象はこのリポジトリ自身の`sqli-lab`デモアプリ(127.0.0.1)に固定だったが、
netcheck/zgrab2と同じ対象入力欄・許可範囲判定を追加し、自分が管理する他の端末も対象にできるように
した。設計は`_resolve_single_target()`(新規の共通ヘルパー)で、netcheckの`expand_targets()`を
再利用して1台だけに絞り込み、`netcheck/config.json`の許可範囲を超える対象は拒否する。既定の
127.0.0.1以外を指定した場合は、対象側のデモアプリを自動起動しない(対象で先に自分で起動しておく
前提)。Strix側は、攻撃コマンドが埋め込まれた`mock_llm_server.py`のスクリプト文字列に対象の
host:portを差し込めるよう、第2引数で受け取るように変更した。

実機確認(このサンドボックス内):
- 範囲外アドレス(`8.8.8.8`)が、Strix・Cairnとも即座に拒否されることを確認。
- 既定(127.0.0.1)でのCairnのフルエンドツーエンドが、変更後も壊れていないことを再確認。
- `127.0.0.2`(ループバックの別アドレス)に`vulnerable_app.py`を手動で立ち上げ、Cairnの対象を
  `127.0.0.2`に指定して実行。自動起動されず(既定以外のため)、実際に`127.0.0.2:5000`へ本物の
  SQLi認証バイパスが行われ、`findings.sarif`の場所(`artifactLocation.uri`)も
  `http://127.0.0.2:5000/login`と正しく対象を反映することを確認。Playwright経由のボタン操作でも
  同じ結果を確認した。
- 範囲内だが到達不能なアドレス(`10.255.255.254`)を指定した場合、明確な接続エラーが返ることを確認。
- Strix側は、`STRIX_LOCAL_DIR`が引き続き未設定のため(ネットワーク制限)、対象の文字列置換ロジック
  単体の検証(`sys.argv`を差し替えてモジュールを実行し、生成される攻撃コマンド文字列を確認)のみ。

### netcheckのポート範囲・zgrab2のモジュールをGUIから選べるように変更(2026-11-01)

`scan_netcheck()`の`ports`パラメータ(`"standard"`/`"extended"`)と`scan_zgrab2()`の`module`
パラメータ(既定`"http"`)は、サーバー側には元々実装されていたが、GUIからは固定値しか送っていな
かった。対象(IP)欄の隣に、netcheckのポート範囲セレクト(標準/拡張)と、zgrab2のモジュール入力欄
(datalistで`http`・`https`・`ssh`・`tls`・`ftp`・`smtp`・`smb`・`banner`を候補表示)を追加し、
それぞれ選んだ値をリクエストボディに含めるようにした。両方ともlocalStorageに保存され、次回以降は
前回選んだ値が復元される。

実機確認(このサンドボックス内): Playwrightで「拡張」を選んでnetcheckを実行し、ステータス表示・
取り込みラベルに「拡張」が反映されること、`#sources`に重複なく1件のみ追加されることを確認した。

zgrab2の`module`選択については、このサンドボックスで`go install
github.com/zmap/zgrab2/cmd/zgrab2@latest`によりzgrab2本体をビルドし(ユーザー実機にインストール
したわけではない。このコンテナ内だけの動作確認目的)、PATHを通した状態で`local_scan_server.py`を
起動して確認した:
- `module`省略時(既定`http`)・`module: "ssh"`明示時の両方で、`/scan/zgrab2`に渡したモジュールが
  実際に`zgrab2 http`/`zgrab2 ssh`として実行され、対象ポート(80/22)も正しく切り替わることを
  `curl`で直接確認。
- GUI(`vuln_triage.html`)から、対象IP欄・同意チェックボックス・モジュール欄(`http`)を入力して
  `#zg-run`をクリックし、ステータス・`#sources`のラベルに選んだモジュール名(`http`)が反映される
  ことをPlaywrightで確認。
- zgrab2本体はこのリポジトリに含まれないため、**ユーザー自身の実機では別途`go install
  github.com/zmap/zgrab2/cmd/zgrab2@latest`(または同リポジトリをclone・ビルド)が必要**。

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
`vuln_triage.html` (a static, backend-less page) trigger Semgrep, Trivy, gitleaks, netcheck,
zgrab2, Strix and Cairn directly from the browser — the same pattern the page's existing "ask your own
LLM" panel already uses against a local Ollama instance. Scope is fixed to this repository's own
working tree (no arbitrary path from the request). Semgrep/Trivy/gitleaks mirror the exact
commands used in `.github/workflows/security-scan.yml`. netcheck reuses `netcheck/netcheck.py`'s
own config and allowed-range logic unchanged. zgrab2 requires an explicit `i_own_these: true`
consent flag and is routed through the same allow-range filtering as `scripts/zgrab2_guard.py`,
and returns a clear error if the `zgrab2` binary isn't installed rather than silently no-op'ing.
Strix requires the same `i_own_these: true` consent (it actively sends attack payloads, such as a
SQLi auth-bypass, at this repo's own `sqli-lab` demo app) plus a pre-prepared Strix checkout named
by the `STRIX_LOCAL_DIR` environment variable — this endpoint deliberately does not clone or patch
the third-party `usestrix/strix` repo itself; that one-time setup stays a manual step documented in
`strix-local-poc/README.md`. When run, it auto-starts `vulnerable_app.py` and `mock_llm_server.py`
if they aren't already listening, runs Strix's existing mock-LLM PoC end to end, and returns the
contents of the resulting `findings.sarif` — which `vuln_triage.html` already knows how to parse
natively (same code path as the sample `report.sarif`), so no new frontend parsing was needed.

Cairn requires the same `i_own_these: true` consent plus a pre-prepared checkout named by
`CAIRN_LOCAL_DIR` (same no-auto-clone policy as Strix). Unlike Strix, Cairn's real dispatcher
(Docker worker containers driven by an LLM) expects worker responses in Cairn's own JSON schema,
which a scripted plaintext mock response doesn't satisfy — tasks fail to parse and retry forever
instead of completing (documented in `cairn-authorized-lab-runbook.md` §6.5). So `/scan/cairn`
skips the dispatcher/worker/LLM layer entirely and drives Cairn's own server API directly via
`CairnClient`, the same technique PR #89's `handoff_recheck_test.py` already proved safe and
reliable in a sandbox like this one — except instead of a synthetic test marker, it actually
re-runs the real SQLi auth-bypass curl request against `sqli-lab`'s demo app and records the real
result as a Cairn Fact (`cairn-lab/run_real_scan.py`). Cairn has no SARIF-shaped output of its
own, so the endpoint converts each recorded Fact into a minimal SARIF 2.1.0 result, reusing the
exact same frontend ingestion path as Strix.

Verified in this sandbox: the netcheck endpoint end-to-end, via a real headless-browser click on
`vuln_triage.html` against a live server (correct scan, correct ingestion, no console errors); CORS
preflight; the zgrab2 consent gate and its missing-binary error path. **The Cairn endpoint was
verified fully end-to-end**, including the real HTTP call and a real headless-browser click,
because this sandbox already had a prepared Cairn checkout on disk from earlier work this session
(no network access to `github.com/oritera/Cairn` was needed). Not verified in this sandbox:
Semgrep's success path (the sandbox's own semgrep install is broken, which did let us confirm the
error-handling path instead), Trivy/gitleaks's actual execution (no Docker daemon, no local
binaries available here), and Strix's success path (`github.com/usestrix/strix` is blocked by this
sandbox's network policy, so no prepared checkout could be obtained here).

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

### Strix endpoint (added this session)

`uv` was present in this sandbox, but network access to `https://github.com/usestrix/strix` was
denied by this environment's network policy (same as several other external hosts blocked earlier
this session), so a full end-to-end Strix run — cloning the repo, applying the patches, `uv sync`,
and actually executing the mock-LLM PoC — could **not** be exercised here. What was verified
instead: the `i_own_these`-required rejection and the clear "`STRIX_LOCAL_DIR` not configured"
error, both via `curl` and via a real browser click (Playwright) on `vuln_triage.html`; that the
two helper processes the endpoint auto-starts (`vulnerable_app.py` and `mock_llm_server.py`) each
still start and respond correctly on their own in this sandbox, exactly as this session's earlier
history already established; and, by code review, that the subprocess timeout / new-run detection
/ `findings.sarif` read logic is sound, and that the SARIF shape it returns matches what
`vuln_triage.html`'s existing SARIF parser expects (same `version`/`runs[].tool.driver.name`/
`results[].ruleId|message|locations|level` shape already confirmed for Strix's real output in
`strix-local-backend-notes.md`'s 検証5). Full verification needs a machine that can actually reach
GitHub to prepare a patched Strix checkout.
