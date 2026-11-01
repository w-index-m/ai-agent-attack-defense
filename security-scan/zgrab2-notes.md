# zgrab2 の取り込み（確認用スキャナの結果をトリアージする）

English summary: see the end of this file.

[zmap/zgrab2](https://github.com/zmap/zgrab2) は、ZMap プロジェクトのアプリケーション層スキャナです（Go 製）。
ZMap が「どの IP のどのポートが開いているか」を調べ、ZGrab2 がそこへ実際に接続して、**サービスの応答（バナー・
ハンドシェイクなど）を詳しく記録**します。本リポジトリでは、**自分の資産の棚卸し結果を `vuln_triage.html` で優先度づけ**
できるようにしました。

> ⚠️ 範囲と方針
> - zgrab2 は**対象へ実際に接続する能動スキャナ**で、**許可範囲を制限する機能を持ちません**。使うのは
>   **自分が所有している、または書面で許可を得た対象だけ**です。公開インターネットへの無差別な走査には使いません。
> - 本リポジトリが追加したのは「**結果の取り込み**」と「**対象を許可範囲に絞るガード**」だけです。
>   攻撃・悪用の手順や、安全機構の回避は含みません。
> - 本セッションでは **zgrab2 のビルドも実行もしていません**。取り込みは、zgrab2 の**ソースと同梱サンプル（`output.json`）で確認した
>   出力構造**に基づき、**架空のデータ**で動作確認しています。実機の出力との差があれば教えてください。

## 1. zgrab2 とは（ソースで確認した範囲）

- ライセンス: Apache-2.0（Go 標準ライブラリの一部をフォークして含む旨が LICENSE に記載）。
- 対応モジュール（`modules/`）: http / tls / ssh / ftp / telnet / smtp / imap / pop3 / mysql / postgres / mssql / oracle /
  redis / mongodb / memcached / mqtt / amqp / smb / rdp / snmp / ntp / ipp / socks5 / pptp、さらに制御系（OT/ICS）の
  modbus / dnp3 / enip / bacnet / fox / siemens / pcworx / proconos / omronfins / gesrtp / codesys / crimson など。
- 入力: 1 行 1 ターゲット（`IP` / `DOMAIN` / `IP, DOMAIN` ほか）。
- 出力: **JSON Lines**（1 行 1 ターゲット）。形は次のとおり。

```json
{"ip":"203.0.113.5","domain":"example.test","data":{"http":{"status":"success","protocol":"http","port":80,
  "result":{"response":{"status_code":200,"headers":{"server":["nginx/1.18.0"]}}},"timestamp":"..."}}}
```

- `status` は `success` のほか `connection-timeout` / `connection-refused` / `protocol-error` など。
  ヘッダのキーは**小文字＋アンダースコア**（例: `content_security_policy`）で、値は配列。

## 2. vuln_triage での取り込み（できること）

`vuln_triage.html` に zgrab2 の出力（JSON Lines）を貼る／ファイルで選ぶと、`status: success` のものから次を指摘にします。
**ツールは自動判別**で、ツール絞り込みに「zgrab2」が加わります。解析はブラウザ内だけで行い、外部へ送りません。

| zgrab2 で見えるもの | 指摘の例 | 重大度 | 防御タグ |
|---|---|---|---|
| DB／キャッシュが応答（redis / mongodb / mysql / postgres / mssql / oracle / memcached） | ネットから直接届いている | 高 | ③ |
| Redis が PING に `PONG`（認証なし） | 認証なしで応答している | 緊急 | ③ |
| telnet が応答 | 暗号化されない遠隔ログイン | 高 | ③ |
| ftp が応答 | 暗号化されない転送 | 中 | ③ |
| rdp / smb / msrpc が応答 | 遠隔操作・ファイル共有の入口 | 高 | ③ |
| 制御系（modbus / dnp3 / enip / bacnet など）が応答 | OT/ICS が外から届く | 高 | ③ |
| mqtt / amqp / snmp / ipp / socks5 / pptp が応答 | 管理・メッセージング系の露出 | 中 | ③ |
| HTTP の `Server` / `X-Powered-By` にバージョン | バージョン露出（偵察の標的） | 低 | R3 |
| 上記や SSH／FTP／Telnet のバナーが古い版（PHP 5/7、Apache 2.0/2.2、IIS 6–8、OpenSSH 1–6 系） | 古いバージョンの可能性 | 中 | R3 |
| HTML のページ(`Content-Type: text/html`、状態 200〜399)で `Content-Security-Policy` なし | CSP がない(API や Content-Type なしは対象外) | 中 | ③CSP |
| TLS が SSLv3 / TLS 1.0 / 1.1 | 古い TLS | 高 | ③ |
| 証明書の期限切れ／30 日以内 | 期限の問題 | 高／中 | ③ |

`status` が `success` 以外（接続できなかった等）は指摘にせず、取り込み元の表示に「未成功 N 件は対象外」と出します。

**注意（過大評価しないために）**
- これは**脆弱性スキャナではなく、露出と表示内容の棚卸し**です。バージョンからの判定は**文字列に基づく推測**で、
  実際のバージョンと違うことがあります。脆弱性の有無は、ベンダのアドバイザリとパッチ状況で確認してください。
- TLS・証明書は、結果の中に `handshake_log` がある場合だけ見ます（モジュールや設定によっては出ません）。
- 対応していない（または名前が違う）モジュールは、黙って無視されます。

## 3. 対象を許可範囲に絞るガード（`scripts/zgrab2_guard.py`）

zgrab2 に渡す前に、対象を検査します。判定ロジックは **netcheck と同じもの（`netcheck/netcheck.py` の `expand_targets`）をそのまま再利用**
しているので、許可範囲の定義は 1 か所です。

- 既定の許可範囲: `127.0.0.0/8` / `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16`。
  自社の公開 IP などを足すときは、`netcheck/config.json` の `allowed_ranges` に**自社が管理している範囲だけ**を書く。
- **1 つでも範囲外・解釈不能が混ざると、何も出力せず終了**（終了コード 2）。
- 実行のたびに `--i-own-these`（自社が管理／書面で許可あり）が必要。一度に扱うのは `max_targets`（既定 256）まで。
- ホスト名の名前解決（DNS）以外、どこにも接続しません。

```bash
# 許可を得た対象に対してだけ。ガードを通した対象を zgrab2 に渡し、結果を vuln_triage に読み込む
printf '192.168.1.10\n192.168.1.0/28\n' \
  | python3 scripts/zgrab2_guard.py --i-own-these \
  | zgrab2 http --port 80 > zgrab2.jsonl
# → zgrab2.jsonl を vuln_triage.html に貼る／選ぶ
```

### zgrab2 本体の入手(2026-11-01)

zgrab2 は本リポジトリに含まれない別の OSS（Go 製）です。`git pull` しただけでは入らず、Go ツール
チェーンで別途ビルド・PATH への配置が必要です。

```bash
go install github.com/zmap/zgrab2/cmd/zgrab2@latest
# → $(go env GOPATH)/bin/zgrab2（既定は ~/go/bin/zgrab2）にバイナリができる。PATH に通しておく。
```

`scripts/local_scan_server.py` の `/scan/zgrab2` は、`shutil.which("zgrab2")` で PATH 上の本体を
検出して実行する(未インストールなら明確なエラーを返す、黙ってスキップしない設計)。上記コマンドで
実際にビルドし、`http`/`ssh` モジュールを指定した `/scan/zgrab2` 呼び出し、および `vuln_triage.html`
の GUI(対象 IP・同意チェックボックス・モジュール欄)からのボタン操作の両方で、実際に zgrab2 本体が
起動し結果を返すことを確認した(サンドボックス内での動作確認。[`local-scan-server-notes.md`](local-scan-server-notes.md)
参照)。

### 軽量な代替: `scripts/http_lite_banner.py`(2026-11-01)

zgrab2本体(Go製)のビルドができない/したくない環境向けに、HTTP/HTTPSへのGETとステータスコード・
応答ヘッダの記録だけを、Python標準ライブラリ(`http.client`/`ssl`)だけで行う軽量な代替を追加した。
zgrab2の完全な置き換えではない(SSH・TLS詳細・SMB・制御系プロトコルなどは非対応)。

- 出力形式を意図的にzgrab2の`http`モジュールと互換にしてあるため、`vuln_triage.html`側の取り込み
  ロジック(zgrab2として自動判別、バージョン露出・EOLバージョン・CSP欠如などの指摘生成)をそのまま
  再利用できる(新しい解析コードは追加していない)。
- 既定で対象の80番(HTTP)・443番(HTTPS、証明書検証なし)の両方にGETを送る。
- zgrab2と同じ許可範囲判定(`netcheck`と共通)・同意フラグ(`--i-own-these`)が必要。

```bash
printf '192.168.1.10\n' | python3 scripts/http_lite_banner.py --i-own-these > httplite.jsonl
# → httplite.jsonl を vuln_triage.html に貼る/選ぶ(zgrab2として自動判別される)
```

GUIからは「HTTPバナー取得(軽量・zgrab2不要)」ボタンで実行できる(`/scan/httplite`)。

### 軽量な代替(続き): `scripts/multi_proto_lite.py`(2026-11-01)

HTTP/HTTPS以外のプロトコルについても、`scripts/multi_proto_lite.py`で軽量な代替を追加した。
対応の深さはプロトコルごとに違う(誠実さを優先し、できる範囲だけを実装):

| モジュール | やっていること |
|---|---|
| `ssh` / `ftp` / `telnet` / `smtp` | 接続して最初の応答(バナー)を読むだけ |
| `mysql` | 接続すると自動で送られてくる初期ハンドシェイクパケットからバージョン文字列を抽出 |
| `redis` | `PING`を送り`PONG`が返るか確認(zgrab2と同じ「認証なしRedis」判定が働く) |
| `memcached` | `version`コマンドを送り応答を確認 |
| `postgres` | `SSLRequest`(8バイトの定型パケット)を送り、`S`/`N`の1バイト応答でTLS対応の有無だけを見る(libpqが実際に使う手順。認証もクエリも行わない) |
| `tls` | Pythonの`ssl`モジュールで実際にハンドシェイクし、プロトコルバージョンを記録。証明書の有効期限は`cryptography`パッケージがあれば読み取る(無ければ省略) |
| `mongodb` / `mssql` / `oracle` | プロトコル固有のハンドシェイクは実装していない。TCP接続の可否だけを確認し、結果にも明示する(バイナリプロトコルが複雑なうえ、検証手段がこの環境に無いため) |

```bash
printf '192.168.1.10\n' | python3 scripts/multi_proto_lite.py --module ssh --i-own-these
```

GUIからは「追加プロトコルを確認(軽量)」ボタンで実行できる(`/scan/multiproto`。モジュール選択・
ポート指定(空欄で既定値)が可能)。

## 4. 防御の観点での位置づけ（R1–R7 / ③）

- **守る側から見た zgrab2**: 外部からの `zgrab2` 的な接続（短時間に多数のポートへ、同じ手順でバナーを取りに来る動き）は、
  **R3（偵察の列挙バースト）** で見ます。ATT&CK では **T1595 Active Scanning**（外から）／**T1046 Network Service Discovery**（内部）。
- **自分の棚卸しとしての zgrab2**: 攻撃者が最初に見る「外から見える表示」を、先に自分で確認して**③（攻撃面の最小化）**につなげる。
  管理面の露出（vCenter / ESXi など）の確認は `netcheck` と併用できます。
- 自律型の攻撃エージェント（Strix / Cairn / ARTEX など）の偵察段階でも、同種の「サービス列挙」が行われるため、
  **露出を先に減らす**のが共通の予防になります。

---

## English summary

[zmap/zgrab2](https://github.com/zmap/zgrab2) is the ZMap project's application-layer scanner (Go, Apache-2.0). It connects to
targets and records detailed protocol transcripts as **JSON Lines** (one object per target:
`{"ip","domain","data":{"<module>":{"status","protocol","port","result"}}}`).

What this repo adds (defensive only):

1. **Ingestion in `vuln_triage.html`** — paste/select zgrab2 JSON Lines; successful module results become prioritized findings
   mapped to this repo's tags (③ exposure minimization, R3 recon/banner exposure, ③CSP). Covers exposed DB/cache/remote-access/ICS/
   messaging services, unauthenticated Redis, version-banner exposure and EOL hints, missing CSP, legacy TLS, and certificate expiry.
   Non-`success` results are skipped and counted. Runs entirely in the browser; nothing is uploaded.
2. **`scripts/zgrab2_guard.py`** — a target allowlist guard in front of zgrab2. It reuses netcheck's range logic (one definition of
   "allowed"), requires `--i-own-these`, caps the target count, and **emits nothing if any target is out of range** (exit 2).

Honest caveats: zgrab2 is an **active scanner with no built-in scope limit** — use it only on assets you own or are authorized to test.
This is an **exposure inventory, not a vulnerability scanner**; version-based findings are string-based guesses. The ingestion was
written from zgrab2's source and bundled sample output and verified with **synthetic data**; zgrab2 itself was **not built or run** here.

> Detection/defense design only. No attack procedures or safety-bypass techniques.
