# detections/drafts/ — 下書き(実ログで未確認)

ここのルールは**下書き**で、`detections/sigma/`などの**R番号つきのルールとは別**。`shared/taxonomy.json`の網羅表にも載せていない
(網羅表の「present」は、「確認済み」と読まれるため)。

## なぜ下書きか

クラウド・CIの監査ログは、このセッションに**実際のログが無く**、イベント名とフィールド名は、AWS CloudTrail・Google Cloud の監査ログ・
GitHub の監査ログの、公開されている形式についての知識に基づいて書いた。合成ログでの確認(`scripts/cloud_audit_check.py`と
`detection-fixtures/cloud_audit_check/`)は、「本物のログで動く」ことの証拠ではない。間違っていても、合成ログのテストは通ってしまう。

## 昇格の条件(R番号を付けて、`sigma/`に移す前に)

1. お使いの環境の**実際のログ**で、対象のイベントが、期待どおりの名前・形で出ることを確かめる(特に、各ファイルの「自信が低い点」)。
2. **普段の操作**で、どれだけ出るか(誤検知)を測る。自動化(CI・IaC)のIDを外す方法を決める。
3. 使っているクラウドに合わせて、フィールド名を、お使いのログ基盤の形に直す。

## 一覧

| ファイル | 見るもの | 根拠 |
|---|---|---|
| `draft_aws_new_access_and_privileged_launch.yml` | 新しいアクセス手段の作成、IAMロールつきのインスタンス起動 | GTIG「ARTEX and Friends」(2026-10-30) |
| `draft_gcp_cloud_hijack_llmjacking.yml` | サービスアカウントのキー、全員公開、AI系APIの有効化、割り当ての引き上げ | GTIG「AI Threat Tracker」(2026-09)のMandiantの事例 |
| `draft_github_workflow_run_deletion.yml` | ワークフロー実行の削除(痕跡消し) | 同上(DUSTMAKER) |

ID単位のバースト・ドライランの連発・owner/editorの付与は、Sigmaでは書きにくい(集計・同一要素の相関が要る)ので、
`scripts/cloud_audit_check.py`だけにある。詳細: [`../../cloud-audit-check-notes.md`](../../cloud-audit-check-notes.md)。
