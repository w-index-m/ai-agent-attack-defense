# php2shell-scanner の使い方（第三者ツール・利用ノート）

[`aancw/php2shell-scanner`](https://github.com/aancw/php2shell-scanner) は、PHP2Shell
(PHPコア自体の重大な2件のメモリ安全性脆弱性——CVE-2026-109618のOOM破壊、CVE-2026-109619の
古いグローバル状態に起因するUAF、各CVSS 9.2、2026-10-21公開。本リポジトリの
[`detections/`](detections/) の R15 参照)に対する露出を確認する、Go製の確認専用スキャナです。
本リポジトリでは実装せず(既に公開・保守されている第三者ツールのため)、R15の検知ルールと
[`tools-dashboard.html`](tools-dashboard.html)から参照しています。このノートは実際に使う際の
手順をまとめたもの。検証者ごとの実施状況は[`external-scanner-verification-log.md`](external-scanner-verification-log.md)にもまとめてある(下記「検証状況」の詳細版)。

> ⚠️ 方針：**第三者ツール**。url モードは対象へ実際にHTTPリクエストを送る能動スキャンです。
> **自分が管理している、または書面で許可を得た対象にだけ使うこと**(netcheck/zgrab2_guardと
> 同じ方針)。利用前に公式リリースの SHA256SUMS を必ず確認すること。

## このツールが確認すること

- スキャナ自体は検知器であって攻撃ツールではない。送る唯一のリクエストは、PHPコードを含まない
  良性の `session.upload_progress` アーミングプローブ(`--canary`を付けない限り)。
- **url**(ブラックボックス): 対象サイトのレスポンスヘッダ/body/phpinfo露出からPHPバージョンを
  特定し、`session.upload_progress.enabled`・`memory_limit`・`fatal_error_backtraces`(8.5)・
  `session.use_only_cookies`・`session.serialize_handler`等、悪用可否を左右する設定も確認。
  SAPIが`Apache 2.0 Handler`(mod_php)かどうかも判定(CVE-2026-109618にとって最悪のケース、
  アプリ側の認証より先にリクエスト後処理が走るため)。
- **local**(このホスト): PHPインタプリタ・バージョン・SAPI(mod_php/php-fpm/webサーバー
  プロセス)を確認し、CLI/Web両方のini・FPMプール・webサーバー設定から上記の設定を確認。
  セッションディレクトリ/ドキュメントルートを、侵害の痕跡(`upload_progress_`マーカーを伴う
  `sess_*`ファイル等)についてもスキャンする。
- **ssh**(リモートホスト): localと同じホスト確認を、SSH経由でリモートホストに対して行う。
- OOM破壊経路自体はプローブしない(証明にはメモリ枯渇が必要で、それ自体がDoSになるため)。
  その代わり、到達可能にする設定を報告する。

## インストール(公式リリース、SHA256検証つき)

```bash
curl -fsSLO https://github.com/aancw/php2shell-scanner/releases/latest/download/php2shell-scanner-linux-amd64.tar.gz
curl -fsSLO https://github.com/aancw/php2shell-scanner/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS

tar -xzf php2shell-scanner-linux-amd64.tar.gz
sudo install php2shell-scanner /usr/local/bin/
```

他プラットフォーム向けのアセット名: `php2shell-scanner-linux-arm64.tar.gz` /
`php2shell-scanner-linux-arm.tar.gz`(armv6) / `php2shell-scanner-darwin-amd64.tar.gz` /
`php2shell-scanner-darwin-arm64.tar.gz` / `php2shell-scanner-windows-amd64.exe`。
静的リンクバイナリなので、ファイル以外に追加のインストールは不要。

## 使い方(自分が管理する対象にだけ)

```bash
# ブラックボックス(自分のサイト)
php2shell-scanner url -u https://your-site.example/
php2shell-scanner url -u https://your-site.example/ --json --fail-on critical

# このホスト自身
php2shell-scanner local
php2shell-scanner local --webroot /var/www/html

# リモートホスト(SSH)
php2shell-scanner ssh -H 10.0.0.5 -U deploy -i ~/.ssh/id_ed25519
```

複数対象(`url`/`ssh`)は繰り返し指定でき、並列実行(`--concurrency`、既定5)される。
`host`・`host:port`・`user@host:port`の形式に対応。疎通できない対象は`SCAN_FAILED`/
`SSH_CONNECT_FAILED`扱いになり、他の対象のスキャンは止まらない。

| フラグ | 対応モード | 意味 |
|---|---|---|
| `--json` | 全て | 結果をJSONで出力 |
| `--fail-on <severity>` | 全て | 指定した深刻度以上で終了コード1(既定`high`、`none`で無効化) |
| `--webroot <dir>` | local, ssh | 追加のドキュメントルート(Apache/Nginx設定から自動検出した上での追加) |
| `--probe` / `--canary` | url | アーミングプローブは既定で有効。`--canary`は、Suricata/YARAルールが拾う無害なPHPコメントを追加 |
| `--crawl` | url | 露出したphpinfoページを探す(既定で有効) |
| `--insecure` | url | TLS検証をスキップ |
| `--agent`, `--password`, `--passphrase`, `--known-hosts`, `--insecure-host-key` | ssh | 認証・ホスト鍵の扱い |

終了コード: `0`問題なし、`1`指定深刻度以上の指摘あり、`2`使い方/実行時エラー。

## バージョン判定の一覧(2026-10-21時点のPHPアドバイザリに基づく)

| ブランチ | 修正版 | 最終脆弱版 |
|---|---|---|
| 8.5 | 8.5.12 | 8.5.11 |
| 8.4 | 8.4.27 | 8.4.26 |
| 8.3 | 8.3.36 | 8.3.35 |
| 8.2 | 8.2.35 | 8.2.34 |
| 8.1以下 | EOL(定常更新なし。7.4/8.0/8.1のバックポートは個別に存在) | 対象として扱う |

修正版未満は`critical`、8.1以下のEOLブランチも`critical`(バックポート有無に関わらず)として
報告される。この表は`scripts/f5_bigip_apm_check.py`等と同じく、ツール開発者が一次情報(PHP
アドバイザリ)から作成したもので、php.net公式アドバイザリでの最終確認を推奨(本ツール自身の
READMEもその旨を明記している)。

## 本リポジトリとの関係

- R15(`detections/sigma/r15_php2shell_worker_crash.yml`等)は、PHP-FPM workerのクラッシュ
  パターンと`X-Powered-By`のバージョンバナーという、ログ/ネットワーク観測に基づく2本立ての
  検知。php2shell-scannerは、それより詳細で確度の高い**ホスト単位の確認**を担う(設定の読み取り、
  侵害痕跡のファイルスキャンまで含む)。
- 本リポジトリの`sqli-lab/auto_vuln_scanner.py`の`check_php2shell()`は、X-Powered-Byの
  バージョン文字列だけを比較する最小限のチェックで、php2shell-scannerのurlモードの一部
  (バージョン判定のみ)に相当する。設定ベースの悪用可否判定や侵害痕跡スキャンは持たない。

## 検証状況

- **リポジトリ所有者の実機(Windows 11 + WSL2)での検証(2026-10下旬)**: 実際に
  `php2shell-scanner`をダウンロード(`curl`でリリースアセット+`SHA256SUMS`取得、
  `sha256sum --check`、`tar -xzf`、`sudo install`)し、`local`モードを実行。
  - このWSL環境のCLI版PHP(`8.5.4`、修正版`8.5.12`未満)を正しく`critical`判定。
  - 悪用経路を成立させる設定もHIGH 2件として正しく検知: `session.upload_progress.enabled=1`
    (CVE-2026-109619の起点)と`fatal_error_backtraces=1`(どちらもPHP 8.5の既定値で、
    特別な設定をしたわけではない)。
  - INFO 3件(`session.upload_progress.cleanup=1`・`memory_limit=-1`等)も参考情報として出力。
  - この時点ではCLI版PHPが入っているだけでWebサーバーとして待ち受けるプロセスは無く、
    外部から攻撃可能な状態ではないことも確認済み。
  - 追加で、R15検知ルール(`detections/sigma/r15_php2shell_worker_crash.yml`)が探す
    php-fpm workerクラッシュパターンの確認として、手作りの3行の合成ログ
    (`/tmp/fpm-test.log`、`[pool www] child 5678 exited on signal 11 (SIGSEGV) ...`を含む)
    を用意し、`php_version_check.py`(本リポジトリ自身のスクリプト)のログ確認機能が
    正しく1件ヒットすることを確認(実際の攻撃成立の証拠ではなく、検知パターン自体が
    正しく動くことの確認)。
  - 結果のスクリーンショットは本人提供のパワポ資料で確認済み。
- **このClaude Codeセッション自身では**、php2shell-scannerのソース(README、`main.go`、
  `internal/`)を取得して読んだのみで、ビルド・実行はしていない(Go言語の実行環境を要する点、
  および実在するPHP2Shell脆弱環境がこのサンドボックスに無い点から)。
- 上記の使い方・フラグ・バージョン表は、ツール自身のREADME(2026-10-22時点の内容)から
  転記したもの。ツールが更新された場合、内容が古くなる可能性がある。利用前に
  `github.com/aancw/php2shell-scanner`の最新READMEを確認すること。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
