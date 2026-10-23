# PHP バージョン確認（確認専用）

`scripts/php_version_check.py`: PHPコア自体の重大な脆弱性チェーン「PHP2Shell」
(CVE-2026-109618のOOM破壊、CVE-2026-109619の古いグローバル状態に起因するUAF、各CVSS 9.2、
2026-10-21公開。[`detections/`](detections/) の R15 参照)の対象になりうるかを確認する。

> ⚠️ 方針：**確認だけ**。php.iniの変更、PHPコードの実行、ネットワークへの送信は一切しない。
> メモリ破壊・エクスプロイトの実行は一切行わない。

## 背景: PHP2ShellとR15の関係

R15(`detections/sigma/r15_php2shell_worker_crash.yml`等)は、php-fpm workerのクラッシュ
パターンと`X-Powered-By`のバージョンバナーという、ログ/ネットワーク観測に基づく2本立ての
検知。本スクリプトはそれを補完する、ホスト側の**バージョン確認**と**ログ確認**ツール:
「このホストのPHPはそもそも対象バージョン範囲にあるか」「workerクラッシュの痕跡が
ログに残っていないか」を直接調べる。

2026-10-21、PHP公式が緊急パッチをリリース(修正版: 8.2.35/8.3.36/8.4.27/8.5.12)。
7.4/8.0/8.1には最小限のソースバックポートが別途公開された。影響が最も大きいのはmod_php
構成(アプリ側の認証チェックより先にリクエスト後処理が走るため、事前認証なしでトリガー
される)。2026-10-22時点でCISA KEVへの掲載は未確認、悪用の評価は情報源間でばらつきがある。

## できること

- **ローカルモード(既定)**: このホストの `php -v` の出力を読み取り、PHP公式アドバイザリの
  修正版/脆弱版と照合する。8.2未満のブランチは、php2shell.com側の「公式の修正版が無い」
  という主張(php.net自身のアドバイザリでは未裏取り)を明記した上で警告する。
- **ログ確認(任意、`--log-path` または `--journalctl-unit`)**: php-fpmのメッセージログ
  (syslog/journal)から、R15のSigmaルールと同じパターン——workerクラッシュ特有の行
  (`exited on signal 11`・`SIGSEGV`等)が、php-fpm文脈の近く(前後3行以内)に現れていないか
  を確認する。これは「workerがクラッシュしたこと」の確認であり、PHP2Shell固有の確証では
  ない(他の原因のクラッシュでも同じ形になりうる)。
- SARIF 2.1.0 での出力にも対応(`--out`)。`vuln_triage.html` に読み込める。

## できないこと・正直な限界

- PHPのバージョン表記はディストリでバックポートされることがあり、本ツールの近似照合では
  正確に判定できない場合がある。
- ログ確認は見つからない場合でも「安全」の確証にはならない(ログローテーション等で既に
  消えている可能性がある)。
- PHP自体のバグを検査するわけではない(動的なエクスプロイト再現・メモリ破壊の実行は
  一切行わない)。バージョンが脆弱範囲にあるかどうかの確認と、クラッシュ痕跡の有無の確認に
  限定している。
- より詳細な確認(実際の悪用可否を左右する設定、`session.upload_progress`等)が必要な場合は、
  第三者の専用ツール[`aancw/php2shell-scanner`](https://github.com/aancw/php2shell-scanner)
  (利用手順は`php2shell-scanner-notes.md`参照)を推奨する。

## 使い方

```bash
python3 scripts/php_version_check.py
python3 scripts/php_version_check.py --out php_check.sarif
python3 scripts/php_version_check.py --log-path /var/log/php-fpm/error.log
python3 scripts/php_version_check.py --journalctl-unit php8.5-fpm
```

## 検証

- このサンドボックス環境には実際にPHP 8.3.6がインストールされており、ローカルモードを
  実行したところ、修正版(8.3.36)未満として正しく`high`判定することを確認した
  (`PHP 8.3.6 (cli) (built: Sep 2 2026 12:56:02) (NTS)`)。
- `assess_version()`のバージョン判定ロジックは、境界値(8.5.11/8.5.12、8.2.34/8.2.35、
  8.1.99、8.6.0)を直接呼び出してユニットテストし、意図した分岐(`high`/`info`/`medium`)に
  なることを確認した。
- ログ確認は、合成したphp-fpmログ(`[pool www] child ... exited on signal 11 (SIGSEGV)`を
  含む行)でユニットテストし、正しく検知することを確認した。php-fpm文脈を伴わない無関係な
  クラッシュ行(合成データ)では検知しないことも確認した。
- `--journalctl-unit`は未検証(このサンドボックスにphp-fpmサービス自体が無いため)。

> 確認・検知の設計に限定。攻撃の実行手順やエクスプロイトコードは含めない。
