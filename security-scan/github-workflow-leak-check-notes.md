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
