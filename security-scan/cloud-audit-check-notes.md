# cloud_audit_check: クラウド・CIの監査ログの下書き(実ログで未確認)

`scripts/cloud_audit_check.py`と`security-scan/detections/drafts/`(2026-11-14追加)。ファイルを読むだけで、何も書き換えない。
標準ライブラリだけで動く。

> **【下書き・未検証】** このセッションには、AWS CloudTrail・Google Cloud の監査ログ・GitHub の監査ログの**実物が無い**。
> イベント名とフィールド名は、公開されている形式についての私の知識に基づく。**合成ログのテストは、名前が間違っていても通る**ので、
> 「本物のログで動く」ことの証拠ではない。R番号を付けず、`shared/taxonomy.json`の網羅表にも載せていない(網羅表の「present」は、
> 「確認済み」と読まれるため)。

## 背景

- GTIGの2026年9月のレポート(利用者が貼り付けた本文に基づく)のMandiantの事例: 露出したGitHubのPATからクラウドに侵入し、全員公開のCloud Runに
  AI基盤を展開、Editor権限の不正なサービスアカウントを作ってキーを書き出し、GPUの割り当て引き上げを要求、AI系APIを有効化。別のマルウェアは、
  GitHub Actionsの実行ログをAPIで削除。
- GTIGの「ARTEX and Friends」(2026-10-30)の記事: 新しいSSHキーペア・Elastic IP・ロールつきの踏み台インスタンス、アカウントの作成、
  ドライラン(権限の探り)の連発、ID単位の数秒〜数十秒の大量操作。記事は、層5「行動と量の変化の検知」の中心に、「シグナルは、ID・送信元・量・順序にあり、
  操作そのものではない」と書いている。

## 探すもの

| ID | 見るもの | 根拠 | イベント名・形への自信(私の知識に基づく) |
|---|---|---|---|
| CLOUD-AWS-1 | `CreateKeyPair`・`ImportKeyPair`・`AllocateAddress`・`CreateAccessKey`・`CreateLoginProfile`・`UpdateLoginProfile`・`CreateUser` | ARTEX記事 | **高**(CloudTrailの有名なイベント名) |
| CLOUD-AWS-2 | `RunInstances`で`requestParameters.iamInstanceProfile`がある | ARTEX記事 | 中(`requestParameters`の形) |
| CLOUD-GCP-1 | `…CreateServiceAccount`・`…CreateServiceAccountKey` | Mandiantの事例 | **高** |
| CLOUD-GCP-2 | `SetIamPolicy`で`allUsers`/`allAuthenticatedUsers`の追加 | Mandiantの事例 | 中〜低(追加された分の記録の場所が、サービスや版で違い得る) |
| CLOUD-GCP-3 | `SetIamPolicy`で`roles/owner`・`roles/editor`の追加 | Mandiantの事例 | 中〜低(同上。追加された分(`bindingDeltas`)が無い形では判定できない) |
| CLOUD-GCP-4 | `…EnableService`・`…BatchEnableServices`で`generativelanguage`・`aiplatform` | Mandiantの事例 | 中(サービス名のイベント名) |
| CLOUD-GCP-5 | `…CreateQuotaPreference`・`…UpdateQuotaPreference` | Mandiantの事例 | 中(どのクオータかは見えない) |
| CLOUD-GH-1 | `workflows.delete_workflow_run`・`workflows.delete_workflow_run_logs` | DUSTMAKER | **低**(後者は、存在するかも自信が無い。GitHubの監査ログは、プランによって、見られる項目が違い得る) |
| CLOUD-BURST | 同じIDが30秒以内に25件以上(既定。変更可) | ARTEX記事(「23秒で27件」) | 高(イベント名に依らない) |
| CLOUD-DRYRUN | 同じIDの`Client.DryRunOperation`が30秒以内に5件以上(既定) | ARTEX記事(ドライランの連発) | 中(AWSのEC2のドライランのエラーコード) |

Sigmaの下書き(`detections/drafts/`)は、集計や同一要素の相関が要るもの(BURST・DRYRUN・GCP-3)を除いて、書いてある。

## 使い方

```bash
python3 scripts/cloud_audit_check.py --log-path cloudtrail.json
python3 scripts/cloud_audit_check.py --log-path audit.jsonl --allow-principal terraform --burst-events 40
```
ログは、JSON配列・JSON Lines・CloudTrailの`{"Records": [...]}`のどれでもよい(形式は自動判別)。お使いのクラウド・CIの、監査ログの
エクスポートの方法で、JSONにして渡す。終了コード: 0(見つからなかった) / 1(見つかった) / 2(読み取りエラー)。

## 確認したこと(合成ログのみ。2026-11-14、このサンドボックス)

- 合成ログ(AWS・GCP・GitHubのイベントの陽性例と、名前が紛らわしいだけの陰性例、10分かけた30件=ゆっくりした操作)で、各IDが期待どおりに出る/出ない。
- 時刻の解析(ナノ秒の端数・タイムゾーン・エポックのミリ秒)、ログの形式(JSON配列・Records・JSON Lines・壊れた行・不明なイベント)、
  除外ID、IDごとの窓の集計、GCPで追加された分が無い形での弱い判定。
- 実装を1つずつ壊して、回帰テストが失敗することを確認した(12通り+単体テストで5通り)。最初に、`--allow-principal`の除外を、
  テストが見逃したので、テストを足して再確認した。
- **実際のログでは、一度も確認していない**。

## 限界

- 上記のとおり、イベント名・フィールド名の正しさは、実ログでの確認が要る。
- ID単位のバーストは、ベースライン(普段の量)が無いと、自動化(CI・IaC)と区別できない。`--allow-principal`で外す。
- Datadog・Elasticの形式は、まだ作っていない(実ログで確認してから)。

## 昇格の条件

`detections/drafts/README.md`の「昇格の条件」に従う: (1)お使いの環境の実際のログで、イベントの名前と形を確かめる、(2)普段の操作での誤検知を測る、
(3)フィールド名を、お使いのログ基盤に合わせる。そのうえで、R番号を付けて、`sigma/`に移し、網羅表に載せる。
