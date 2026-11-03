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
| `POST /scan/httplite` | `scripts/http_lite_banner.py`(zgrab2が無くても使える軽量な代替)で、対象の80番(HTTP)・443番(HTTPS、証明書検証なし)へGETを送る | ボディに`i_own_these: true`が無いと一切実行しない。許可範囲判定はnetcheck/zgrab2と同じ。Python標準ライブラリのみで動き、外部バイナリ不要。出力はzgrab2の`http`モジュールと互換の形式で返すため、GUI側はzgrab2として自動判別する(SSH/TLS詳細など他プロトコルは非対応) |
| `POST /scan/multiproto` | `scripts/multi_proto_lite.py`(zgrab2が無くても使える軽量な代替)で、`module`で指定したプロトコル(ssh/ftp/telnet/smtp/redis/memcached/mysql/postgres/tls/mongodb/mssql/oracle/smb/rdp/snmp/mqtt/amqp/ipp/socks5/pptp/modbus)へ接続する | ボディに`i_own_these: true`が無いと一切実行しない。許可範囲判定はnetcheck/zgrab2と同じ。`port`省略時はモジュールごとの既定ポート。Python標準ライブラリのみで動く(TLSの証明書有効期限だけは`cryptography`パッケージが無いと省略される)。mssql/oracle/pptpは実機未検証(自作の模擬応答での自己テストのみ、結果に明示)。OT/ICSはModbus(読み取り専用コマンドのみ)だけに対応、他(DNP3/BACnet/Siemens等)は非対応。出力はzgrab2の各モジュールと互換の形式で返すため、GUI側はzgrab2として自動判別する |
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
エンドポイント自身が自動で起動する(`local_scan_server.py`をCtrl+Cで止めると一緒に止まる)。

### Windows 11(PowerShell)での手順

コマンドはすべてPowerShell構文(`$env:名前="値"`)。cmd.exeの`set`や`%TEMP%`、bashの`export`は
PowerShellでは使えない。環境変数は、`local_scan_server.py`を起動する**同じウィンドウ**で設定する。

```powershell
cd C:\Users\<ユーザー名>\ai-agent-attack-defense
git pull
# 必要なときだけ(ポート5000/5001を他のソフトが使っている場合)
$env:VULN_APP_PORT="5100"; $env:VULN_INTERNAL_PORT="5101"
python scripts\local_scan_server.py
```

起動メッセージに、`STRIX_LOCAL_DIR`/`CAIRN_LOCAL_DIR`の設定状態とデモアプリのポートが表示される。
すべてのスキャン要求は、実行前と実行後に、改ざんを検知できる監査ログ`results\local-scan\audit.jsonl`
へ記録される(書き込めない場合は実行しない)。検証は`python scripts\audit_log.py verify results\local-scan\audit.jsonl`
(詳細: [`ai-security-roadmap-mapping.md`](ai-security-roadmap-mapping.md))。
別のPowerShellウィンドウで自己診断を実行すると、環境・ポート・各機能の疎通をまとめて確認できる
(結果は`results\local-scan\selfcheck.txt`にも保存される)。

```powershell
python scripts\local_scan_selfcheck.py          # 数十秒
python scripts\local_scan_selfcheck.py --full   # Semgrep/Trivy/gitleaksも実行(数分)
```

Strixは、`local`バックエンドがUnix専用の部品を使うため、Windows上で起動したサーバーでは実行できない
(押すとすぐにエラーと手順を表示する)。画面はWindowsのブラウザのまま、WSL2(Ubuntu)でポート8767の
2つ目のサーバーを起動し、接続設定の「Strix用エンドポイント」に`http://localhost:8767`を入れる。
手順: [`strix-local-poc/README.md`](strix-local-poc/README.md)の「Windowsの場合」。

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

### zgrab2の軽量な代替(`/scan/multiproto`)をさらに拡張: MongoDB/MSSQL/Oracleの本実装、
SMB/RDP/SNMP/MQTT/AMQP/IPP/SOCKS5/PPTP、Modbus(読み取り専用)に対応(2026-11-01)

これまで「TCP接続の可否だけ」だったMongoDB/MSSQL/Oracleを、各プロトコル仕様どおりの最初の1往復
(MongoDBはOP_MSGのhello、MSSQLはTDSのPRELOGIN、OracleはTNSのCONNECT)に置き換えた。あわせて、
これまで未対応だったSMB・RDP・SNMP・MQTT・AMQP・IPP・SOCKS5・PPTPを追加し、OT/ICS(制御系)は
Modbusの読み取り専用コマンド(Read Holding Registers、ファンクションコード0x03、1レジスタのみ)
だけに限定して追加した。DNP3/BACnet/Siemens S7等の他OT/ICSプロトコルは、実機が無く検証できない
ことと、不正なパケットで機器が予期せぬ挙動を起こすリスクが相対的に高いことから、引き続き見送って
いる。

対応の深さは今回もプロトコルごとに使い分けている:
- **SMB/RDP/SNMP/MQTT/SOCKS5/Modbus**: 各プロトコル仕様どおりの最小限の1往復を実装し、応答を
  正しくデコードする(SMB2 Negotiateのdialect、RDPの選択セキュリティプロトコル、SNMPのsysDescr、
  MQTTのCONNACK、SOCKS5の選択認証方式、Modbusのレジスタ値/例外応答)。
- **AMQP/MongoDB**: プロトコル仕様どおりの最初の1往復(プロトコルヘッダ/OP_MSG hello)は送るが、
  応答本体の完全なデコードはせず、印字可能な文字列を抜き出す簡易抽出に留めている(フィールド
  テーブル/BSONの完全なパーサーは実装していない)。
- **MSSQL/Oracle/PPTP**: 各プロトコル仕様に基づいて実装したが、このサンドボックスには実機(本物の
  SQL Server/Oracle Database/PPTPサーバー)が無く、自作の模擬応答での自己テストしか行えていない。
  実機での結果と異なる可能性がある(GUI・結果にも明示)。

実機確認(このサンドボックス内): `apt-get install`で実際のサーバーが用意できるものは、本物の
サーバーに対して確認した。

| モジュール | 確認方法 | 結果 |
|---|---|---|
| SMB | 実際の`samba`(smbd、非特権ポート) | SMB2 Negotiate Responseから`SMB 3.0.2`を正しく取得 |
| RDP | 実際の`xrdp` | X.224/RDP Negotiation Responseから選択セキュリティプロトコル(標準セキュリティ)を正しく取得 |
| SNMP | 実際の`net-snmp`(snmpd、UDP) | `sysDescr.0`を正しく取得 |
| MQTT | 実際の`mosquitto` | CONNACK(accepted)を正しく取得 |
| AMQP | 実際の`rabbitmq-server` | Connection.Start応答から`RabbitMQ`・`3.12.1`等を簡易抽出で取得 |
| IPP | 実際の`cups`(cupsd) | HTTP 200・IPP status-codeを正しく取得 |
| SOCKS5 | 実際の`dante-server`(danted) | 選択認証方式(認証不要)を正しく取得 |
| MongoDB | 自作の模擬OP_MSG応答サーバー(実機無し) | hello応答から`version`・`gitVersion`を簡易抽出で取得 |
| Modbus | 自作の模擬Modbus TCPサーバー(実機無し) | Read Holding Registersの応答値を正しく取得 |
| MSSQL | 自作の模擬TDS応答サーバー(実機無し) | PRELOGIN応答からサーバーバージョンを正しく取得 |
| Oracle | 自作の模擬TNS応答サーバー(実機無し) | REFUSE応答のタイプと理由文字列を正しく取得 |
| PPTP | 自作の模擬SCCRP応答サーバー(実機無し) | Control Message Type・Result Codeを正しく取得 |

この過程で見つかり、修正したバグ:
- **SMB**: Negotiate ResponseのDialectRevisionフィールドのオフセットを誤っていた(`body[2:4]`
  (実際はSecurityMode)を読んでいたのを`body[4:6]`に修正)。実際のSambaから常に`0x0001`
  (SecurityMode値)が返ってきたことで気づいた。
- **PPTP**: 自作のテスト用クライアント実装自体は正しかったが、応答を解析する側でControl Message
  Typeのオフセットを誤っていた(8バイトの共通ヘッダー(length+PPTP_MESSAGE_TYPE+Magic Cookie)の
  直後から始まる、という理解が最初漏れていた)。
- **AMQP**: 簡易抽出で取り出す文字列の件数上限(`max_items`)が小さすぎて、製品名・バージョン
  (フィールドテーブルの後半にある)が切り捨てられていた。上限を増やして修正した。

Modbusはこのサンドボックスに実機(PLC等)が無いため自己テストのみ。ただし実装自体は、Read Holding
Registers(読み取り専用)という、nmapのmodbus-discoverスクリプトなど資産検出ツールが広く使う標準的
な手法に限定しており、書き込み系コマンドは一切送らない。

### zgrab2の軽量な代替(`/scan/multiproto`)を拡張: SSH/FTP/Telnet/SMTP/Redis/Memcached/MySQL/
PostgreSQL/TLS詳細/MongoDB/MSSQL/Oracleに対応(2026-11-01)

`scripts/http_lite_banner.py`(HTTP/HTTPSのみ)に続き、`scripts/multi_proto_lite.py`で対応
プロトコルを広げた。「スクラッチでzgrab2相当を全部作れるか」との相談に対し、全20以上の
プロトコルを一度に実装するのはリスク(検証手段がない環境での誤判定)が大きいと判断し、
対応の深さをプロトコルごとに使い分けている(誠実さを優先):

- **バナーをそのまま読むだけ(低リスク)**: SSH・FTP・Telnet・SMTP・MySQL。接続して最初の
  応答を読むだけで、こちらから何も送らない(MySQLだけ、サーバーが自動で送ってくる初期
  ハンドシェイクパケットからバージョン文字列を取り出す)。
- **最小限のコマンドだけ送って応答を見る(中リスク)**: Redis(`PING`→`PONG`を確認、
  zgrab2と同じ「認証なしRedis」判定が働く)、Memcached(`version`コマンド)、
  PostgreSQL(`SSLRequest`という8バイトの定型パケットを送り、`S`/`N`の1バイト応答で
  TLS対応の有無だけを見る。libpqが実際に使う手順で、認証もクエリも行わない)。
- **TLS**: Pythonの`ssl`モジュールで実際にハンドシェイクし(自前のTLS実装はしない)、
  プロトコルバージョンを記録。証明書の有効期限は、`cryptography`パッケージ(今回の
  サンドボックスには既に入っていた)があれば読み取り、無ければその項目だけ省略する
  (`pip install cryptography`で有効化)。
- **MongoDB/MSSQL/Oracle(やらないことにした部分)**: プロトコル固有のハンドシェイクは
  実装していない。バイナリプロトコルが複雑なうえ、この環境には実機の検証手段(実際の
  MongoDB/MSSQL/Oracleサーバー)が無く、誤判定のリスクの方が大きいと判断したため。
  TCP接続の可否だけを確認し、結果にも「プロトコルハンドシェイクは未実装」と明示する。

出力は、いずれもzgrab2の対応モジュールと互換の形式(`vuln_triage.html`側の取り込みロジック
をそのまま再利用、新しい解析コードは追加していない)。GUIには「追加プロトコルを確認(軽量)」
ボタンと、モジュール選択・ポート指定(空欄で既定値)を追加した。

実機確認(このサンドボックス内): 実際に動くサービスを用意して確認した。
- Redis: `redis-server`を実際に起動し、認証なしで`PING`→`PONG`が返ること、zgrab2互換の
  「認証なしでRedisが応答している」(critical)・「データベース/キャッシュが直接届く」(high)
  の両方の指摘が生成されることを確認。
- SSH/FTP/Telnet/SMTP/MySQL/Memcached: それぞれのプロトコルの初期応答を模した簡易サーバーを
  用意し、バナー・バージョン文字列(SSHは`OpenSSH_8.9p1`、MySQLは`8.0.35-fake`など)が正しく
  抽出されることを確認。
- PostgreSQL: `SSLRequest`に`S`で応答する簡易サーバーに対し、`tls_supported: true`が正しく
  返ることを確認。
- TLS: 自己署名証明書を使った簡易HTTPSサーバーに対し、バージョン(`TLSv1.3`)・証明書の
  有効期限が正しく取得され、GUI経由(Playwright)で「証明書の期限が近い」指摘が実際に
  生成されることを確認(自己署名証明書を有効期限1日で発行したため)。
- MongoDB/MSSQL(実際にはsqli-labの5000/5001番ポートで代用): 接続成功時に「TCP接続のみ確認」
  の結果が返ることを確認。
- エラー系: 接続拒否(`connection-refused`)、平文ポートへのTLS接続時の
  `ssl.SSLError`の正しい分類(`protocol-error`、`http_lite_banner.py`と同じ修正パターン)を確認。
- `/scan/multiproto`エンドポイント(`curl`)・GUIのボタン操作(Playwright)の両方で、一連の
  動作に不具合がないことを確認。

**追記(2026-11-01、本物のサーバーでの再確認)**: 上記は簡易サーバー(バナー文字列のみ模倣)での
確認だったため、「本物のOpenSSH/vsftpd/Postfix/MySQLでも動くか」との指摘を受け、このサンドボックス
に実際の`openssh-server`・`vsftpd`・`postfix`・`mariadb-server`(`apt-get install`)を導入して
再確認した(いずれも非特権ポートで、既存ポートと衝突しないよう個別起動):
- **OpenSSH**(`sshd -p 2022`): `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20`を正しく取得、
  software抽出も`OpenSSH_9.6p1`で正しい。
- **vsftpd**(`listen_port=2021`、匿名ログイン許可): `220 (vsFTPd 3.0.5)`を正しく取得。
  (最初、匿名/ローカルログイン両方を無効にした設定で試したところ`500 OOPS: ...`が返ってきたが、
  これはvsftpd側の仕様どおりの挙動で、本スクリプトの不具合ではない。匿名ログインを許可する設定に
  直して通常の220バナーを確認した。)
- **Postfix**(`master.cf`に非特権ポート2525のsmtpdを追加): `220 vm ESMTP Postfix (Ubuntu)`を
  正しく取得。
- **MariaDB**(`mariadbd --port=3307`、MySQL互換): 初期ハンドシェイクパケットから
  `5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1`を正しく抽出(先頭の`5.5.5-`は、MariaDBが古いMySQL
  クライアントとの互換性のために付ける実際の仕様どおりの表記で、抽出バグではない)。
- `/scan/multiproto`エンドポイント・GUI(Playwright、MariaDB相手)の両方で、本物のサーバーに対する
  一連の動作(「データベース/キャッシュが直接届く」指摘の生成まで)を再確認した。
- 確認後、導入した4サービスはすべて停止した(このリポジトリの常設インフラではなく、今回の検証限り)。

### zgrab2の軽量な代替(`/scan/httplite`)を追加(2026-11-01)

zgrab2本体(Go製)のビルドが使えない/したくない環境向けに、`scripts/http_lite_banner.py`(標準
ライブラリのみ、外部バイナリ不要)で、対象の80番(HTTP)・443番(HTTPS、証明書検証なし)へのGETと
応答ヘッダの記録だけを行う軽量な代替を追加した。zgrab2の完全な置き換えではなく(SSH・TLS詳細・SMB・
制御系プロトコルなどは非対応)、出力形式を意図的にzgrab2の`http`モジュールと互換にすることで、
`vuln_triage.html`側の取り込みロジック(zgrab2として自動判別、バージョン露出・EOLバージョン・CSP
欠如などの指摘生成)をそのまま再利用し、新しい解析コードは追加していない。GUIには「HTTPバナー取得
(軽量・zgrab2不要)」ボタンを追加した(対象IP・同意チェックボックスは既存の共通欄を再利用)。

実機確認(このサンドボックス内):
- `grab()`単体で、既存のsqli-labデモアプリ(127.0.0.1:5000、平文HTTP)へのGETが成功し、zgrab2の
  実際の出力と同じ構造(`server`・`content_type`などスネークケースのヘッダ、`status_code`)が返る
  ことを確認。
- 自己署名証明書を使った簡易HTTPSサーバーを立て、TLS経路(証明書検証なし)でも成功することを確認。
- 平文ポートへTLSで接続した場合、`ssl.SSLError`が`OSError`のサブクラスであるため当初
  `connection-timeout`と誤分類していたバグを発見・修正し(`protocol-error`に変更)、再確認した。
- `/scan/httplite`エンドポイント(`curl`)・GUIのボタン操作(Playwright)の両方で、対象への接続拒否
  (ポート80/443が閉じている場合)が正しくエラーとして扱われ(`#sources`に「未成功2件は対象外」)、
  二重発火等の不具合がないことを確認。

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

### Windows実機でStrixを試した際に見つかり、修正したバグ(2026-11-02)

ユーザーがWindows PCで実際にStrixセットアップ(`STRIX_LOCAL_DIR`設定・v1.7.0タグへのcheckout・
パッチ適用・`uv sync`)を完了させた後、GUIから「Strixを実行」を押すと
「対象(127.0.0.1:5000)またはmock_llm_server.pyの起動を確認できませんでした」というエラーで
失敗した。

原因は、`vulnerable_app.py`(DB_PATH)・`strix-local-poc/mock_llm_server.py`(LOG_PATH)の両方が、
ログ/DBファイルの保存先として`/tmp/...`というLinux専用のパスをハードコードしていたこと。Windowsでは
`/tmp`が存在しないため、両プロセスとも起動直後にファイルオープンでエラーになり、ポート5000・8899の
どちらも開かず、`_ensure_background()`が20秒待っても確認できないまま上記のエラーメッセージになって
いた。

`os.path.join(tempfile.gettempdir(), ...)`に置き換えて修正(`tempfile.gettempdir()`はWindowsでは
`C:\Users\<user>\AppData\Local\Temp`のような実在するパスを返す)。このサンドボックス内で、修正後に
両プロセスが正常に起動し、`vulnerable_app.py`の`/login`SQLi認証バイパスも従来どおり動作することを
確認した。

`security-scan/strix-local-poc/mock_llm_server_chain.py`・`mock_llm_server_deserialize.py`にも
同様の`/tmp`ハードコードがあるが、これらは`local_scan_server.py`からは呼ばれない独立したPoCスクリプト
で、かつペイロード自体がUnixシェルコマンド(`curl`/`printf`/`cat`)前提のデモなので、今回は対象外とした。

### Windows実機での続報: ポート5000/5001が常時専有されているケースへの対応(2026-11-02)

上記の`/tmp`修正後、同じユーザーのWindows PCで改めてStrixを試したところ、今度は`vulnerable_app.py`
が起動時に`アクセス許可で禁じられた方法でソケットにアクセスしようとしました`(WinError 10013)で
失敗した。実機での切り分け(`netstat -ano`・`netsh interface ipv4 show excludedportrange`)の結果、
Hyper-V/WSL2のポート除外範囲が原因ではなく、**「agent」という名前の常駐プロセス(管理者権限が無いと
詳細情報が見えず、エンドポイント保護ソフト等と推測される)がポート5000/5001を常時専有している**ことが
判明した(`taskkill`も「アクセスが拒否されました」で失敗し、ユーザー権限では終了できない)。

`vulnerable_app.py`自体は`VULN_APP_PORT`/`VULN_INTERNAL_PORT`環境変数でポートを変更できる設計に
既になっていた(コメント: 「WSL2 mirrored networkingがWindowsのサービスとポートを共有する場合」を
想定)が、`local_scan_server.py`側(`scan_strix`・`scan_cairn`)はポート5000を複数箇所にハードコード
しており、この環境変数を認識できなかった。`local_scan_server.py`に`VULN_APP_PORT`(既定`5000`)を
追加し、ハードコードされていた`5000`をすべてこの変数に置き換えた。`local_scan_server.py`を起動する
前に`$env:VULN_APP_PORT="5100"`(PowerShell)のように指定すれば、GUI経由のStrix/Cairn自動起動も
同じポートで動くようになる。

あわせて、この調査の過程で見つけたもう1つの不具合も修正した: Strix自身が内部的に失敗した実行
(`run.json`の`status`が`"failed"`。原因は下記「訂正」参照)でも、`findings.sarif`は0件のまま書き出されてしまい、
`scan_strix()`はそれをそのまま「成功(0件)」として返していた。GUI上は✅の成功表示になり、実際には
スキャンが一度も実行されていないことに気づけない設計になっていた。`run.json`の`status`を確認し、
`"failed"`等が含まれる場合は明確なエラー(`strix.log`の末尾付き)として返すよう修正した。

実機確認(このサンドボックス内): `VULN_APP_PORT=5100`を指定して`local_scan_server.py`を起動し、
`vulnerable_app.py`が実際にポート5100で自動起動すること、`/login`のSQLi認証バイパスがそのポートでも
正しく動作することを確認。`run.json`の`status`判定ロジックも、ユーザーが実際に遭遇した
`{"status": "failed"}`を模したフィクスチャで、正しくエラーとして検出されること(および通常の
`"completed"`等では誤検知しないこと)を確認した。Strix本体はこのサンドボックスには実機が無く
(`STRIX_LOCAL_DIR`未設定)、この部分の実機確認はユーザーの手元での再試行待ち。

### 全体の見直しで見つかり、修正した点(2026-11-03)

これまでの変更をまとめて見直した結果、以下を訂正・修正した。

- **訂正: WindowsでのGUI実行が失敗した原因**。上の節では「`mock_llm_server.py`に接続できず
  LLM CONNECTION FAILEDで止まっていた」と書いたが、これは誤り。GUI実行時の
  `requests.jsonl`には疎通確認(「OK」を返すだけの要求)が2回記録されており、モックへの接続は成功
  していた。`strix.log`では、`Creating sandbox session ... (backend=local)`の直後にエラーの
  テレメトリが送られて終了している。LLM CONNECTION FAILEDが出たのは、ユーザーが手動でStrixの
  CLIを実行した際にモックを起動していなかったためで、別の事象だった。`strix-local-backend.patch`の
  `local`バックエンドはOpenAI Agents SDKの`UnixLocalSandboxClient`(Unix専用)を使うため、
  **Windowsネイティブではサンドボックス作成の時点で失敗する可能性が高い**(WSL2上での実行を推奨)。
  `scan_strix()`は、Windowsで`run.json`が失敗を示した場合にこのヒントをエラーに含めるようにした。
- **修正: GUIからStrixを2回以上実行すると、2回目以降は必ず0件になる**。`mock_llm_server.py`は
  台本の何手目かを「サーバー起動以降のログ行数」で数えていたが、`local_scan_server.py`は起動済みの
  モックを使い回すため、2回目の実行では最初の1手目から`finish_scan`(終了)が返っていた。あわせて、
  対象IPを変えて再実行しても、モックは最初の起動時の対象へ攻撃コマンドを組み立てていた。
  `scan_strix()`がStrix実行の直前にモックのログを空にし、今回の対象を`target.txt`に書き込み、
  モック側は要求ごとにそれを読み直すようにした。連続3回の実行を模した試験で、修正前の挙動
  (2回目は最初から`finish_scan`)の再現と、修正後に毎回最初から台本が進み、変更後の対象へ
  向くことを確認した。
- **修正: Oracle(TNS)のCONNECTパケット**。接続記述子の位置を示すオフセットを58と宣言しながら、
  実際には42バイト目から書いていた。本物のリスナーは記述子を16バイトずれた位置から読むことになる
  (自作の模擬サーバーは中身を検証していなかったため、自己テストでは見逃していた)。予約領域を
  正しい長さにし、宣言と実際の位置(58)、パケット長が一致することを確認した。
- **修正: 古いTLSを検出できなかった**。`tls`モジュールはPythonの既定コンテキストを使っていたため
  最低バージョンがTLS1.2で、TLS1.0/1.1しか話さないサーバーとは握手自体が失敗し、`protocol-error`
  になっていた(GUIの「古いTLSが使われている」判定が働かない)。最低バージョンを下げたコンテキストを
  使うようにし、TLS1.0専用の試験サーバーで、修正前は握手失敗、修正後は`TLSv1`を記録できることを
  確認した。

### Windows対応の総点検と、実機エラーから見えたミスの傾向(2026-11-03)

Windows 11で実際に使ってもらう中で、pull・再試行が何度も必要になった。実機のエラーログを振り返り、
同じ種類のミスを残さないよう、関係するPythonスクリプト一式を総点検した。このサンドボックスはLinuxの
ため、Windows実機での確認はできていない。日本語版Windowsの条件(文字コードcp932)を
`PYTHONIOENCODING=cp932`と`-X warn_default_encoding`で再現して確認した。

**実機エラーから見えたミスの傾向**

| 傾向 | 実際に起きたこと | 対策 |
|---|---|---|
| Linuxでの動作をそのまま前提にした | `/tmp`の決め打ちで、デモアプリとモックLLMがWindowsで起動直後に落ちた | `tempfile.gettempdir()`に統一 |
| 文字コードを指定しなかった | (総点検で発見。まだ実機では未遭遇)日本語Windowsでは、ファイル書き込みやリダイレクト出力で、cp932に無い文字(絵文字・U+FFFD等)があると例外で落ちる | `open(..., encoding="utf-8")`と、JSON Lines出力の標準出力をUTF-8に固定 |
| 設定値を部品ごとに別々に持った | デモアプリはポートを環境変数で変えられるのに、サーバー側は5000を固定で書いていた | `VULN_APP_PORT`をサーバー側でも参照し、起動メッセージに表示 |
| 案内したコマンドのシェルを取り違えた | PowerShellの利用者にcmd.exe構文(`set`・`%TEMP%`・`dir /o-d`)を案内し、往復が増えた。複数ウィンドウを使う手順で手順漏れも誘発した | エラーメッセージの環境変数例をOSに合わせて表示し、手順書はPowerShell構文に統一 |
| 前提バージョンを手順に書かなかった | パッチはStrix v1.7.0専用なのにcloneの手順にタグ指定が無く、`git apply`が失敗した | 手順とエラーメッセージに`git checkout v1.7.0`を明記 |
| 失敗を成功として表示した | Strixの内部失敗(`run.json`の`status=failed`)でも、0件のSARIFを✅として取り込み、真因の発見が遅れた | `run.json`を確認してエラーとして返す |
| ログの証拠と合わない結論を出した | モックへの疎通確認が成功している記録があるのに「モックLLMに接続できなかった」と説明した。本当の原因は、Unix専用部品(`UnixLocalSandboxClient`)を使う`local`バックエンドだった。パッチ内のクラス名から事前に気づけた | 結論を出す前に、ログの各行と矛盾しないか照合する。Windowsでの失敗時はエラーに注意書きを出す |
| 自作の模擬サーバーが、自分の誤りを再現してしまった | PPTPの応答オフセットやTNSの記述子オフセットの誤りが、同じ理解で作った模擬サーバーでは「成功」に見えた | 模擬サーバー側で、受け取った値と仕様上の位置を突き合わせる。可能な限り本物のサーバーで確認する |
| 状態が持ち越されることを想定しなかった | 使い回すモックLLMの手数カウントで2回目以降が0件になった。自動起動したデモアプリが残り、ポートを塞いだ | 実行ごとにリセットし、サーバー停止時に子プロセスも止める |

**総点検の結果(このコミットで修正したもの)**

- `mock_llm_server.py`: ログの読み書き3箇所で文字コード未指定。日本語Windowsでは、絵文字を含む要求で
  例外になる(`-X warn_default_encoding`で実行時に3箇所すべてを検出)。
- `multi_proto_lite.py`・`http_lite_banner.py`: `> out.jsonl`のようにファイルへ保存すると、標準出力が
  cp932になり、Telnetバナー等に含まれる文字で落ちる(cp932を再現して`UnicodeEncodeError`を確認)。
- `local_scan_server.py`: 環境変数の設定例をbash構文だけで出していた(PowerShellでは使えない)。
  自動起動した子プロセスがサーバー停止後も残っていた(Ctrl+Cで止まることを確認)。起動時に
  `STRIX_LOCAL_DIR`等が効いているか分からなかった。
- Strixの手順とエラーメッセージに、バージョン指定(`git checkout v1.7.0`)が無かった。
- 自己診断スクリプト`scripts/local_scan_selfcheck.py`を追加した(上の「Windows 11(PowerShell)での手順」
  参照)。ポートの判定では、使用中(WinError 10048)とウイルス対策ソフト等によるブロック
  (WinError 10013)を区別する。

全エンドポイントを、正常系・同意なし・範囲外・不正なモジュール名・不正なポート・前提ツール無しの
各ケースで呼び出し、500(内部エラー)が1件も出ないこと、実行時の文字コード警告がゼロになったことを
確認した。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。

---

### StrixボタンがWSL2で必ず失敗していた原因と修正(2026-11-03)

WSL2で「Strix用エンドポイント」を使って実行したところ、約4秒で`run.json`のstatusが`failed`になった。
Strixのエラー出力の最後は`LocalDirReadError: failed to read local dir artifact: /home/<ユーザー>/strix`。

- 原因: `/scan/strix`は、Strixの作業コピー(`STRIX_LOCAL_DIR`)をカレントフォルダにして`-t ./`で
  起動していた。`-t ./`はカレントフォルダの中身を丸ごと実行環境へコピーするが、作業コピーの中の
  `.venv`にはシンボリックリンク(`bin/python`等)があり、SDK(openai-agents 0.19)はシンボリックリンクを
  読まない(`symlink_not_supported`)。そのため、OSを問わず**必ず**失敗していた。これまでStrixの成功を
  確認できていたのは、別に用意した対象フォルダから`uv run --project ~/strix`で起動した手動の検証
  だけで、このエンドポイント自体を最後まで動かしたことは無かった(サンドボックスのネットワーク
  制限を理由に、確認を後回しにしていた)。Windowsでの失敗も、この原因が重なっていた可能性がある。
- 修正: 毎回、シンボリックリンクの無い一時フォルダに`sqli-lab`の`.py`だけをコピーし、そこから
  `uv run --project <STRIX_LOCAL_DIR> strix -n -t ./`で起動する。成功時は一時フォルダを消し、
  失敗時はログを調べられるよう残す(場所はエラー表示に出る)。
- 画面にも、エラー出力とログの末尾を表示するようにした(これまではサーバーが返しても捨てていた)。
- 確認: このサンドボックスで、実際のStrix(v1.7.0にパッチ適用、openai-agents 0.19.0)を、
  `curl`とブラウザ(Playwright)の両方から2回続けて実行し、どちらもSQLi認証バイパス(CWE-89)の
  指摘1件を取り込めた。監査ログの検証もOK。
- 教訓(ミスの傾向に追加): 「依存する環境が無いので確認できない」機能を、部品ごとの確認だけで
  「動くはず」として渡していた。今回のサンドボックスには、実は必要なもの(Strixの作業コピーとuv)が
  揃っていた。確認できないと判断する前に、手元にあるもので最後まで動かせないかを先に確かめる。

### Windows 11+WSL2の実機で、Strixボタンの動作を確認(2026-11-03)

上の修正(一時フォルダからの起動)の後、ユーザーのWindows 11 PCで確認した。

- 構成: Windows(PowerShell)で`local_scan_server.py`(8766)、WSL2(Ubuntu、Python 3.14)で
  `STRIX_LOCAL_DIR=~/strix VULN_APP_PORT=5100 VULN_INTERNAL_PORT=5101 python3 scripts/local_scan_server.py --port 8767`。
  `vuln_triage.html`はWindowsのブラウザで開き、「Strix用エンドポイント」に`http://localhost:8767`を指定。
- Windowsから`curl.exe http://localhost:8767/health`で`"platform": "linux"`が返り、WSL2のサーバーへ
  `localhost`で届くことを確認。
- 「Strixを実行」で✅。「2. 全体像」に高1件(SQLi認証バイパス)が入り、攻撃連鎖の「ログイン画面の
  SQLインジェクション」に1件該当。`/tmp/mock_llm/requests.jsonl`は4行(失敗時は1行)で、Strixが
  模擬LLMとやり取りしながら最後まで進んだことも確認。
- 注意: 攻撃の手順は模擬LLMの台本であり、AIが自律的に脆弱性を見つけたことを示すものではない。
  確認できたのは、Strixの実行の仕組み(実行環境の作成・コマンド実行・レポート生成)が、この構成で
  正しく動くこと。
- 途中でつまずいた点: 古いサーバーが動いたまま起動し直すと`OSError: [Errno 98] Address already in use`
  になる(`pkill -f "local_scan_server.py --port 8767"`で止めてから起動する)。WSL2用のコマンドを
  PowerShellに入力してしまう(先に`wsl`でUbuntuに入る)。

### 同日の続き: HTTPバナー取得と、要求がWSL2側のサーバーに届いていた件(2026-11-03)

- 「HTTPバナー取得(軽量)」を押すと、`127.0.0.1:80`から「CSPがない」(中)・「応答にバージョン情報が
  出ている」(低)の2件が取り込まれた(ポート80で動いているWebサーバーの実際の応答)。
- その後Cairnを押すと、`CAIRN_LOCAL_DIR`未設定のエラーの設定例が`export CAIRN_LOCAL_DIR=...`
  (Linux向け)だった。Windowsのサーバーなら`$env:...`と表示する作りなので、要求はWSL2側のサーバーが
  受けていた。エンドポイント欄は`http://localhost:8766`で、PowerShellの`curl.exe`では8766が
  `"platform": "windows"`、8767が`"linux"`を返しており、サーバー自体は正しく分かれていた。
- 原因の推定(未確定): ブラウザは`localhost`をIPv6の`::1`で先に試す。WSL2の`localhost`転送は
  `::1`側でも待ち受けるため、WSL2側に`--port`無しで起動した8766番のサーバーが残っていると、
  ブラウザだけがそちらにつながる。`127.0.0.1`を指定すれば、この食い違いは起きない。
- このため、上のHTTPバナー取得も、WSL2側のサーバーで実行された可能性がある(ボタン自体が動くことは
  確認できた)。次回は、エンドポイントを`http://127.0.0.1:8766`にして確かめ直す。
- 画面の改善点(未対応): 要求に返事をしたサーバー(Windows/Linux)を結果の表示に出すと、この種の
  食い違いにすぐ気づける。Strixの指摘の場所が、Strix自身の出力どおり`SECURITY.md`と表示される
  (実際の場所`/login`はSARIFの`logicalLocations`に入っている)。

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
