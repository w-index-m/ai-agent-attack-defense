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

## 2026-11-08追記3: R5をGate 3に区分(`verification-gates.md`棚卸しとの整合)

R5は、Gambit Securityが自社で発見・回収した攻撃者ステージングサーバーに基づく一次報告
(2026-09-22)を出典としており、Gambit自身の一次情報源にあたる。直接fetchはブロックされて
いるため、複数の独立した二次情報源の一致した報告で確認した。これによりR5をGate 3に区分
した。検知ロジック自体(パスパターン一致)は本リポジトリ独自の構成のままである。


## 2026-11-09追記: CI回帰に組み込んだ

これまで「このセッション内で一度、合成ログで動作確認した」のみで、継続的な再検証の手段が
無かった。`security-scan/detection-fixtures/`に陽性/陰性の合成ログを同梱し、
`scripts/run_detection_regression.py`が`.github/workflows/security-scan.yml`の`scan`
ジョブから毎回(PR・push・毎日の定期実行)このスクリプトを実行し、陽性入力は必ず検知・
陰性入力は必ず誤検知0件であることを確認するようになった。壊れた場合は
`results/detection_regression.json`に記録され、`scripts/summarize.py`経由でCIの要約にも
出る。詳細は`scripts/run_detection_regression.py`自身のdocstring参照。

## R8-DB(書き込み主体がDBサーバーの場合)の追加(2026-11-14)

GTIG/Mandiantの記事「ARTEX and Friends」(2026-10-30)は、ARTEXが、アプリのSQLインターフェース経由で
DBのログ出力の機能を使い、JSPのWebシェルを作らせた例を詳しく述べている。R8の設置側は、書き込み主体を
問わずWebルート配下の実行可能コンテンツを拾うので、この手口も既存ルールで拾える見込みだったが、
**書き込み主体がDBサーバー(`mysqld`・`mariadbd`・`postgres`)のとき**は、通常まず起きないため、
高確度の別ルールとして区別した(`r8_webshell_placement_and_spawn.yml`の3つ目のドキュメント)。
`file_event_check.py`は、この場合を`[R8-DB]`と表示する(それ以外は従来どおり`[R8]`)。

- Linuxのfile_eventのみ。記事は影響を受けたサーバーのOSを明記していないため、Windows(`mysqld.exe`)は未対応。
- 未実装: DB側のログ(クエリログ・監査ログ)で、ログ出力先の設定が変更されたことを見る検知。
- 確認(合成ログ): `mysqld`によるWebルート配下の`.jsp`の作成は`[R8-DB]`、`php`によるものは`[R8]`と表示。
  `mysqld`によるWebルート外のログ、`mysqld`によるWebルート配下の`.csv`、`apt`によるWebルート配下の`.php`
  (デプロイ用ツールとして除外)は一致しない。`run_detection_regression.py`に表示を確かめるケースを追加し、
  判定を無効にすると失敗することを確認した。

## R34(非エディタによる、AI・IDEの設定ファイルの書き込み)の追加(2026-11-14)

GTIGの2026年9月のレポート(利用者が貼り付けた本文に基づく)が、マルウェア(DUSTMAKER)が、AI・IDEの隠し設定
ディレクトリ(`.claude/`・`.vscode/`・`.cursor/`)に書き込み、IDE/AI拡張がワークスペースを開くたびにコマンドが
動くようにし、設定ファイルでAIアシスタントにコマンドを実行させること、また、別の集団(MIDNIGHT NEPTUNE)が
Claude CLIのhooksを改ざんしたことを報告している。R32(エージェントが自分のメモリを書く2段の形)とは別の、
**外部のプロセスが、実行に関わる設定を書く1段の形**として、`file_event_check.py`に`[R34]`を追加した。

- 対象: `.claude/settings.json`・`settings.local.json`・`hooks/`・`commands/`、`.vscode/tasks.json`・`settings.json`・
  `launch.json`、`.cursor/mcp.json`・`rules/`、`.codex/config.toml`、`.mcp.json`、`.cursorrules`。
  **レポートが挙げているのはディレクトリ名までで、このファイル名の一覧は、「コマンドを実行できる設定の置き場所」
  として、このリポジトリが選んだもの**(探索的ヒューリスティック。特定キャンペーンのシグネチャではない)。
- 除外(既知の書き込み元): エディタ(`code`・`cursor`・`codium`・`vim`など)、`git`、AIアシスタント自身
  (`claude`・`codex`)。`node_modules/`・`site-packages/`配下も除外。
- 誤検知の見込み: Claude CodeをNodeで動かしている場合、許可の記録でnodeが`.claude/settings.local.json`を書く。
  nodeを許可すると、JavaScriptのローダーも見逃すので、環境ごとに判断する。scaffoldingや構成管理ツールの書き込みも対象になる。
- Linux形式のパスのみ(Windowsのパスは未対応)。
- 確認(合成ログ): `node`・`bash`・`python3`・`curl`による4件が`[R34]`。エディタ・`git`・設定ではない`.claude/cache`・
  `node_modules`配下は一致しない。`run_detection_regression.py`に表示を確かめるケースを追加し、判定を無効にする・
  書き込み元の除外を外す・依存フォルダの除外を外す、の3通りで、失敗することを確認した。

