# 検知ルール（Strix / Cairn / Hermes 攻撃連鎖向け）

`../defense-detection-notes.md` の検知ロジック（R1–R6）を、実スタック向けに具体化したもの。
**検知コンテンツのみ**で、攻撃手順や安全機構の回避方法は含まない。

| ルール | 意味 | Sigma | Falco | Datadog | Elastic |
|---|---|---|---|---|---|
| R1 | サーバ系から LLM API への外向き通信 | ✅ | — | ✅ | ✅ |
| R2 | 特権 cap / host ネット / privileged コンテナ起動 | ✅(aux) | ✅ | — | ✅ |
| R3 | 偵察的 Web 列挙バースト | ✅ | — | ✅ | ✅(threshold) |
| R4 | サーバからのメッセージング API（C2 的） | ✅ | — | ✅ | ✅ |
| R5 | 永続化（cron / systemd timer）の新規作成 | ✅ | ✅ | — | ✅ |
| R6 | 相関（連鎖を束ねる） | — | — | — | ✅(EQL seq) |
| R7 | 1 親プロセスが多種のセキュリティツールを短時間に連続実行（ローカルLLM型でも残る） | ✅ | ✅(aux) | — | ✅(threshold+card) |

## 使い方・注意

- **閾値・資産ゾーンは各環境のベースラインに合わせて必ず調整**（例: R3 の件数、R1/R4 の送信元ゾーン定義）。
- ドメイン/イメージ名リストは例示。自組織で使う正規の LLM/メッセージング先は allowlist 化し、残りを異常として扱う。
- フィールド名はプロダクトのスキーマ（ECS / Datadog 標準属性 / Falco フィールド）に依存するため、環境に合わせて読み替える。
- これらは**単体シグナル**。本連鎖の検知力は相関（R6）にあるため、SIEM 側で時系列相関を組むこと（`../defense-detection-notes.md` の §2 R6 / §4 参照）。

## ファイル

- `sigma/` — ベンダ非依存の Sigma ルール（SIEM 変換前提）
- `falco/cairn-ai-agent.yaml` — Falco（コンテナ/ホストのランタイム検知）
- `datadog/` — Datadog ログ検知ルール（クエリ例）
- `elastic/` — Elastic Security 検知ルール（KQL/EQL・ECS）。`elastic-detection-rules.ndjson` を Kibana に取り込み（取り込み手順・調整箇所は `elastic/README.md`）
