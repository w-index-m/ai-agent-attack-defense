# 外部スキャナ検証ログ: php2shell-scanner / Node2Shell Radar

本リポジトリが参照している2つの**外部・第三者ツール**(php2shell-scanner、Node2Shell Radar)
について、「誰が」「何を」実際に検証したかを一本にまとめた記事。詳細な使い方・フラグ・
インストール手順はそれぞれの個別ノート([`php2shell-scanner-notes.md`](php2shell-scanner-notes.md)、
[`brotli-node2shell-radar-notes.md`](brotli-node2shell-radar-notes.md))を参照。このページの
目的は、検証結果が会話やパワポに埋もれて記録から漏れないようにすること(下記「教訓」参照)。

## php2shell-scanner — リポジトリ所有者の実機(WSL)での検証

[`aancw/php2shell-scanner`](https://github.com/aancw/php2shell-scanner) は、PHP2Shell
(CVE-2026-109618/CVE-2026-109619、R15)の確認専用スキャナ。

- **検証者**: 本リポジトリの所有者本人。**このClaude Codeセッションではない。**
- **環境**: Windows 11 + WSL2。
- **やったこと**: 公式リリースをダウンロード(`curl`でアセット+`SHA256SUMS`取得、
  `sha256sum --check`、`tar -xzf`、`sudo install`)し、`local`モードを実行。
- **結果**:
  - WSL環境のCLI版PHP(`8.5.4`、修正版`8.5.12`未満)を正しく`critical`判定。
  - 悪用経路を成立させる設定をHIGH 2件として正しく検知:
    `session.upload_progress.enabled=1`(CVE-2026-109619の起点)、
    `fatal_error_backtraces=1`。どちらもPHP 8.5の既定値で、特別な設定をしたわけではない。
  - INFO 3件(`session.upload_progress.cleanup=1`・`memory_limit=-1`等)も参考情報として出力。
  - この時点ではCLI版PHPが入っているだけで、Webサーバーとして待ち受けるプロセスは無く、
    外部から攻撃可能な状態ではないことも確認済み。
  - 追加で、R15検知ルール(`detections/sigma/r15_php2shell_worker_crash.yml`)が探す
    php-fpm workerクラッシュパターンの確認として、手作りの3行の合成ログ
    (`/tmp/fpm-test.log`、`[pool www] child 5678 exited on signal 11 (SIGSEGV) ...`)を用意し、
    `php_version_check.py`(本リポジトリ自身のスクリプト)のログ確認機能が正しく1件
    ヒットすることを確認。実際の攻撃成立の証拠ではなく、検知パターン自体が正しく動くことの
    確認。
- **結果の提供方法**: スクリーンショット付きのパワポ資料として共有された。

## Node2Shell Radar — READMEとソースの食い違い発見 + 実機検証

[`Secragon/node2shell-radar`](https://github.com/Secragon/node2shell-radar) は、
Node2Shell/HTTP2Shell(CVE-2026-111497、R24/R25)の、ドメイン/URL単位でのサーバー側
露出確認ツール。

- **検証者**: このClaude Codeセッション自身。
- **発見**: ツール自身のREADMEは「デスクトップGUIのみ、CLIやフラグはドキュメント化
  されていない」と書いているが、ソース(`pyproject.toml`の`[project.scripts]`、
  `radar/cli.py`、`radar/__main__.py`)を読むと、`PySide6`(GUI)に一切依存しない
  完全headlessなCLI(`python -m radar --cli`)が実在することが分かった。README読解だけでは
  分からなかった食い違い。
- **やったこと**: `add_repo`で読み取り専用clone→GUI依存を除いたvenvをセットアップ
  (`pip install --no-deps -e .` + `httpx`/`dnspython`/`cryptography`のみ)→自分で立てた
  使い捨てのローカルNode.jsサーバー(127.0.0.1:5055、`sqli-lab`とは別プロセス)を対象に、
  CLIを3パターン実行。
- **結果**:
  | パターン | サーバーの応答ヘッダ | 実際の判定(`verdict`) |
  |---|---|---|
  | バージョンヘッダ無し | `X-Powered-By: Express`のみ | `Unconfirmed` |
  | 脆弱バージョンを報告 | `X-Node-Version: 22.22.0`(修正版22.23.4未満) | `At risk` |
  | 修正済みバージョンを報告 | `X-Node-Version: 22.23.4` | `Fixed version` |

  いずれも`decoder_patch_status`は常に`"Unverified remotely"`で、ツール自身が主張する
  「リモートからの確定的な証拠ではない」という限界とも一致。判定に使われた修正版表
  (`FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}`)も、
  `python-brotli-check-notes.md`に記載済みのNode.js公式の修正版と一致することを確認した。

## 教訓: 外部ツールの検証結果は、その都度マークダウンに残す

今回、php2shell-scannerの実機検証(リポジトリ所有者がWSLで実際に行ったもの)は、別の
会話(パワポ資料のレビュー)で確認されていたにもかかわらず、`php2shell-scanner-notes.md`
には長らく反映されず、「このセッションでは未実行・未検証」という記述だけが残っていた
(PR [#81](https://github.com/w-index-m/ai-agent-attack-defense/pull/81)で修正)。

**この種の抜け漏れを防ぐためのルール**:

- 外部ツールを**誰かが実際に動かした**(このセッションか、リポジトリ所有者の実機か、を
  問わず)結果は、その場でではなく、**気づいた時点で**該当ノートファイルの「検証状況」
  節に書き残す。会話・スクリーンショット・パワポだけに残して満足しない。
- 「検証者」を必ず明記する(このセッション自身の検証なのか、第三者/所有者本人の実機
  検証なのか)。混同すると、どこまで裏取りされているかが分からなくなる。
- README等ツール自身のドキュメントを鵜呑みにせず、**気になる場合はソースを実際に読む/
  動かして確認する**(Node2Shell RadarのCLI発見がその例)。

> 確認・検知の設計に限定。攻撃の実行手順やエクスプロイトコードは含めない。
