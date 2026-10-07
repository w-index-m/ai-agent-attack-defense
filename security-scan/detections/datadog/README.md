# Datadog 検知ルール（例）

Datadog Cloud SIEM / Log Detection Rules 向けのクエリ例。`*.json` はルール定義の骨子で、
`queries`/`cases` の考え方を示すもの。実際の属性名（`@network.destination.name`,
`@network.client.zone` など）は取り込みパイプラインのスキーマに合わせて読み替えること。

| ファイル | 対応 | 検知 |
|---|---|---|
| `r1_llm_egress.json` | R1 | サーバ系から LLM API への外向き通信 |
| `r3_recon_burst.json` | R3 | 管理画面パス列挙バースト（4xx 多発） |
| `r4_messaging_c2.json` | R4 | サーバからのメッセージング API 通信 |

注意:
- 閾値（`cases` の件数）・評価ウィンドウ・`@*.zone` の定義は各環境でチューニングする。
- 正規の LLM/ChatOps 利用先は allowlist 化し、ルール側で除外する。
- 単体シグナルのため、Datadog の Signal Correlation で R1+R3(+特権コンテナ) を束ねると
  `../defense-detection-notes.md` の R6（相関）に相当する高確度検知になる。
