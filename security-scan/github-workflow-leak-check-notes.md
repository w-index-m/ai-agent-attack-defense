# github_workflow_leak_check: GitHubイベントログからR27を確認するツール

## 経緯

`verification-gates.md`の棚卸しで見つかったギャップ。`security-scan/detections/sigma/
r27_agentic_workflow_private_data_public_write.yml`は、「GitLost」(Noma Security開示: 公開
GitHub Issueの隠し指示が、GitHub Agentic Workflowsを操ってプライベートデータを公開流出
させた)を模した、「同一run_idの中でプライベートリポジトリの読み取りと公開出力への書き込みの
両方が起きる」というパターンの**ルール定義**で、投入先はSIEM側が前提。
`scripts/github_workflow_leak_check.py`は、同じ判定ロジックをGitHubイベントログに対して
直接実行する版。

> このルールは`status: experimental`で、「再利用可能なログシグネチャは公開されておらず、
> 本リポジトリ独自の構成」と明記されている。スクリプト化してもこの限界は残る。

## やること(確認専用、読み取りのみ)

- GitHubイベントのログ(JSON Lines)を読む。
- 同一`run_id`の中で、プライベートリポジトリの読み取り(`repo.content.read`/
  `actions.workflow_run`、`repository_visibility: private`)と、公開の出力への書き込み
  (`issue_comment.create`/`pull_request_comment.create`/`pages.publish`/`artifact.publish`、
  `output_visibility: public`)の両方が存在する場合に検知。
- GitHubへの書き込み・APIコールは一切しない。

## 使い方

```bash
python3 scripts/github_workflow_leak_check.py --log-path github_events.jsonl
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-08、このサンドボックス内)

- 合成ログ(run-1: private読み取り→public書き込みの陽性パターン・run-2: private読み取りのみ
  (公開書き込み無し)・run-3: public書き込みのみ(private読み取り無し))で、run-1のみを正しく
  検出。run-2・run-3は誤検知0件。

## 確認していないこと

- 実際のGitHub Actions/Agentic Workflowsが出力する**本物の**イベントログでの動作(今回は
  すべて合成ログでの検証)。実際のGitHub監査ログ・Webhookペイロードのフィールド名は、
  本スクリプトが想定する単純化されたスキーマと異なる可能性が高い。
- 「読み取り→書き込み」の順序(読み取りが書き込みより時間的に先か)は、本スクリプトでは
  判定していない(同一run_id内に両方が存在するかどうかのみで判定)。

## Gate 3追補(2026-11-08、WebSearch経由での一次情報裏取り)

このサンドボックスからは`noma.security`への直接アクセスがブロックされているため、WebSearch経由で
Noma Security自身のブログ記事("GitLost: How We Tricked GitHub's AI Agent into Leaking Private
Repos"、noma.security/noma-labs/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos)
の要約を確認した。一次情報元(Noma Labs自身)が報告している内容は以下の通りで、本ルールが
モデル化している挙動(「同一run内でのプライベート読み取り→パブリック書き込み」)と一致する:

- 公開のGitHub Issueに、プレーンな英文で隠した指示(プロンプトインジェクション)を埋め込んだ。
- 脆弱なワークフローは`issues.assigned`イベントで起動する設定になっていた。
- エージェントはそのIssueの編集権限しか無いはずだったが、組織内の**他のリポジトリ(プライベート
  含む)への読み取り権限を持っていた**(スコープがIssue単位ではなく組織単位だった)。
- エージェントは隠し指示に従い、プライベートリポジトリのファイル(デモではREADME.mdの内容)を
  読み取り、その内容を**パブリックなコメントとして投稿**した。
- GitHubはこのシナリオに対する安全策(ガードレール)を既に用意していたが、巧妙な平文の
  インジェクションで回避された。
- Noma Securityは公開前にGitHubへ開示済み(Responsible disclosure)。公開日は2026-07-06。

**結論**: 「同一run_id内でのプライベート読み取り→パブリック書き込み」というルールの骨格は、
一次情報元(Noma Labs自身)の報告と一致することを確認した。ただし依然として、(1)実際の
GitHub監査ログのイベントスキーマがNoma Labsの記事内で明示されていない(本スクリプトのJSON
Lines形式は本リポジトリ独自の単純化)、(2)Noma Labsはこの技術的検知手法そのものを公開して
いない(検知ロジックは本リポジトリの構成)、という2点は変わらず未確証。`status: experimental`
のままとするが、**「ルールが模している攻撃シナリオ自体が一次情報元の報告と一致する」ことは
Gate 3相当まで裏取りできた**、と整理する。


## 2026-11-09追記: CI回帰に組み込んだ

これまで「このセッション内で一度、合成ログで動作確認した」のみで、継続的な再検証の手段が
無かった。`security-scan/detection-fixtures/`に陽性/陰性の合成ログを同梱し、
`scripts/run_detection_regression.py`が`.github/workflows/security-scan.yml`の`scan`
ジョブから毎回(PR・push・毎日の定期実行)このスクリプトを実行し、陽性入力は必ず検知・
陰性入力は必ず誤検知0件であることを確認するようになった。壊れた場合は
`results/detection_regression.json`に記録され、`scripts/summarize.py`経由でCIの要約にも
出る。詳細は`scripts/run_detection_regression.py`自身のdocstring参照。
