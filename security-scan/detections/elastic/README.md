# Elastic 向け検知ルール（R1–R7）

`../defense-detection-notes.md` の検知ロジックを **Elastic Security 検知ルール**（KQL / EQL・ECS フィールド）に
落とし込んだもの。**検知コンテンツのみ**で、攻撃手順や安全機構の回避方法は含まない。

## ファイル

| ファイル | 対応 | ルール種別 |
|---|---|---|
| `r1_llm_egress.json` | R1 | query (KQL) |
| `r2_privileged_container.json` | R2 | query (KQL) |
| `r3_recon_burst.json` | R3 | threshold |
| `r4_messaging_c2.json` | R4 | query (KQL) |
| `r5_persistence.json` | R5 | query (KQL) |
| `r7_multitool.json` | R7 | threshold（cardinality） |
| `r6_correlation_eql.json` | R6 | eql（sequence） |
| `elastic-detection-rules.ndjson` | 全部 | **Kibana 取り込み用**（上記 7 本を1ファイルに） |

## 取り込み手順（Kibana Security）

1. Kibana → **Security → Rules → Detection rules (SIEM)** → **Import**。
2. `elastic-detection-rules.ndjson` をアップロード。
3. すべて `"enabled": false` で入るので、内容・インデックス・閾値を確認してから有効化する。

> 検知エンジン API を使う場合は `POST kbn:/api/detection_engine/rules/_import`（`.ndjson` を multipart で送信）。
> バージョンにより受け付けフィールドが多少異なるため、取り込み後に UI で各ルールを一度開いて保存すると確実。

## 必ず環境に合わせて調整する箇所

- **インデックスパターン**（各ルールの `index`）… 例として `logs-*` / `auditbeat-*` / `logs-endpoint.events.*` 等を入れてある。自組織のデータビュー名に置換。
- **ゾーン判定 `labels.src_zone`**（R1/R4）… 「サーバ系かどうか」を表す自組織のフィールドに置換。無い場合は `source.ip` の CIDR 条件などに書き換える。
- **閾値**（R3 の件数、R7 の `cardinality.value`）… 自環境のベースラインに合わせる。
- **ドメイン allowlist**（R1/R4）… 正規に使う LLM / メッセージング先は除外条件を追加。
- **コンテナ監査のフィールド**（R2）… Falco / auditbeat / k8s audit でフィールド名が異なる。`container.security_context.privileged` や `process.args` を実データに合わせる。

## ECS フィールドの対応（目安）

| 用途 | 使用フィールド（例） |
|---|---|
| 宛先ドメイン | `destination.domain` |
| 送信元ゾーン | `labels.src_zone`（プレースホルダ） |
| HTTP ステータス / パス | `http.response.status_code` / `url.path` |
| コンテナ特権 | `container.security_context.privileged` / `process.args` |
| ファイル作成 | `event.category:file` / `event.type` / `file.path` |
| プロセス親子 | `process.parent.entity_id` / `process.name` |

## R6（相関）について

`r6_correlation_eql.json` は**単一インデックス内**の代表的な相関（EQL sequence：同一親プロセスで偵察ツール→別ツール）。
R1(egress)＋R2(コンテナ)＋R7(多ツール) のような**クロスインデックス相関**は、Elastic の
**ルール・オン・ルール（アラートを入力にした検知）**や、横断データビュー上の EQL/ES|QL で構成するのが実務的。
`../defense-detection-notes.md` の R6 の考え方に沿って、自環境のインデックス構成で配線すること。

## Sigma からの変換（別経路）

`../sigma/` のルールは `sigma-cli` / pySigma の Elasticsearch バックエンドで KQL / Lucene / ES|QL / EQL に
変換できる。本フォルダは「変換済み・取り込める形」を直接用意したものだが、Sigma を正本として運用し
変換で追従する方針でもよい。

> すべて検知・防御の設計に限定。ガバナンス層（スキル/安全機構の無効化＝G1–G6, T1562）は
> ネットワーク/ホストのこれらとは観測点が異なり、エージェント監査ログ側で見る（`../../defense-detection-notes.md` §7 参照）。
