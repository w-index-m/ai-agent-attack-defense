# file_event_check: ファイル書き込みログからR5・R8(設置側)を確認するツール

## 経緯

`verification-gates.md`の棚卸しで見つかったギャップ。R5(`r5_persistence_cron_systemd.yml`)・
R8設置側(`r8_webshell_placement_and_spawn.yml`の前半)は、どちらも「ファイル書き込みイベント」
という同じログ源(auditdのfile_event等)が前提の**ルール定義**で、投入先はSIEM側が前提。
`scripts/file_event_check.py`は、この2つを同じファイル書き込みログに対して直接実行する版。

## やること(確認専用、読み取りのみ)

- ファイル書き込みイベントのログ(JSON Lines)を読む。
- **R5**: `/etc/cron.*`・`/var/spool/cron/*`・`/etc/systemd/system/*`・`/etc/crontab`で始まる、
  または`.timer`・`.service`・`crontab`で終わるパスへの書き込みを検知。
- **R8(設置側)**: `/var/www/`・`/usr/share/nginx/`等のWebルート配下への、`.jsp`・`.war`・
  `.php`等の実行可能コンテンツの書き込みを検知(`dpkg`・`rpm`等の正規デプロイツールは除外)。
- ファイルの作成・変更は一切しない。

## 使い方

```bash
python3 scripts/file_event_check.py --log-path file_events.jsonl
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-08、このサンドボックス内)

- 合成ログ(R5該当2件・R8該当1件・正規デプロイツールによる書き込み1件・無関係なファイル
  書き込み1件)で、該当3件を正しく検出。正規デプロイツール(`dpkg`)による`.php`ファイル
  書き込みは正しく除外(誤検知0件)。

## 2026-11-08追記: R20(Markdown散発書き込み)・R28(エディタ拡張機能のSSH鍵作成)を追加

「gate0止まりのしょり」の指示で追加。どちらも`status: experimental`で、ルール自体に「二次情報源
からの推測で、確認済みのシグネチャではない」と明記されている。

- **R20**: 同一プロセス(`process_guid`/`host`でグループ化)が、既知ドキュメントパス(`/docs/`等)
  以外で、異なる.mdファイルを4個超・異なるディレクトリに2個超、散発的に書き込むパターン。
- **R28**: `Cursor`・`Code - Insiders`・`code`・`extensionHost`を含む親プロセスが、SSH鍵や
  `authorized_keys`を作成・変更するパターン。

合成ログ(R20該当: 5個の.mdファイルを3ディレクトリに散発書き込み・既知docsパス配下の.mdは
除外対象として6件/R28該当: Cursor extensionHostによるauthorized_keys作成1件・通常のターミナル
からのssh-keygenは対象外)で正しく検出し、誤検知0件を確認。

## 2026-11-08追記1.5: R20の一次情報源での再確認(Gate 3、訂正1件を発見)

`unit42-ai-assisted-intrusion.ja.md`/`.en.md`が既に裏取りしていた「構造化Markdownでの
エージェント間情報受け渡し」(Unit 42記事本文)を、WebSearch経由で改めて再確認した。
結果は変わらず一致(Unit 42本文: "Structured Markdown files passing information between
agents and sessions")。ただし再調査の過程で、**Unit 42自身が記事に訂正を入れていた**ことが
分かった: "Updated Sept. 3, 2026, at 5:25 a.m. PT to clarify that the attack was an
intrusion, and not a ransomware attack."――当初「ランサムウェア攻撃」として報じられていた
この事案は、一次情報元自身により「侵入事案(ランサムウェアではない)」と訂正済み。R20自体の
検知ロジックは「ランサムウェア」という語に依存していないため実害は無いが、`unit42-ai-assisted-intrusion.ja.md`/`.en.md`に訂正を追記した(詳細はそちらを参照)。

## 2026-11-08追記2: R28の一次情報源での裏取り(Gate 3へ)

R28が模した事件(Cursorマーケットプレイスの改ざん版Claude Code拡張機能)について、Cursor公式の
セキュリティ通知(https://cursor.com/blog/claude-code-extension-security-notice)を一次情報源として
確認できた。確認できた具体的事実:

- 対象: `Anthropic.claude-code` v2.1.312/2.1.313、2026-10-29 02:27〜13:35 PT(約11時間)、
  最大約5,000ユーザー。
- 手口: 拡張機能ロード時に無条件で実行され、攻撃者の`ssh-ed25519`公開鍵(ラベル
  `svc-telemetry`)を`authorized_keys`に追記、ローカルSSHを有効化し、攻撃者IP
  `134.209.82.225`へポート22/8099でリバースSSHトンネルを試行。
- Cursor自身が「通常ホストでは管理者権限が無い限り失敗する」と明言。
- **当初「IOC未公表」としていたが、これは現在誤り**。Cursorは改訂版通知でSHA-256ハッシュ・
  攻撃者IP・`svc-telemetry`文字列・macOSのLaunchAgent/`~/.config`下のファイル・Windowsの
  タスク/スタートアップスクリプトのパスをIOCとして公表済み。
- Cursorは「アンインストールのみでは不十分な場合がある」と明言(悪意のあるコードが拡張機能
  フォルダ外に永続化アーティファクトを設置できるため)。

これにより、Sigmaルール(`r28_ide_extension_ssh_persistence.yml`)の`description`・
`references`を更新した。ただし本スクリプト自体の判定ロジック(親プロセス名の文字列一致)は
IOC(ハッシュ・IP・鍵ラベル)を使った確認済みシグネチャではなく、依然として汎用的な
ビヘイビアプロキシである点は変わらない。

## 確認していないこと

- 実際のauditd等が出力する**本物の**ファイルイベントログでの動作(今回はすべて合成ログでの
  検証)。
- R5の「新規作成」という要件は、本スクリプトでは「このパスパターンへの書き込みイベントが
  ログにあるかどうか」で判定しており、既存ファイルへの変更と新規作成を区別していない
  (ログ側に`event_type`があれば区別できるが、本スクリプトは現状どちらも拾う設計)。
