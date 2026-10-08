# ARTEX 防御解析（一次情報・静的レビュー）

English: [`artex-analysis.en.md`](artex-analysis.en.md)

自律型ペネトレ AI エージェント **ARTEX**（[Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)）を、
本リポの防御研究（Strix/Cairn/Hermes と同じ粒度）で**アーキ分解し、防御観測点に対応づけた**もの。

> ⚠️ 方針と範囲：
> - **公開ソースの静的レビューに限定**（クローンして読んだだけ。**実行・ビルド・依存インストールはしていない**）。
> - **攻撃の実行手順・兵器化・安全機構の回避は作らない／載せない**。スキルの攻撃内容も転記しない。
> - ARTEX は**実際に攻撃を実行**するツール。動かすなら**所有／書面認可の対象のみ**。
> - **サプライチェーン注意**：外部コードを信頼できない前提で静的に読んだだけで、悪性コードの不在は保証しない。自動更新（selfupdate）・MITM プロキシ・外部 LLM への送信を持つため、実行は十分に隔離した環境で、かつ認可範囲でのみ。

## 1. 概要・素性

- **AI 自主渗透测试系统**（自律型ペネトレ）。作者は GitHub の **Autumn-27**。ライセンス **AGPL-3.0**。
- **百度安全応急響応中心(BSRC)** 主催「Agent+」攻防能力チャレンジ**優勝**（9/3 成都決勝・8チーム）とされる。
- 本リポのクローン時点のバージョン **0.3.15**（スクショは 0.3.14）。関連プロジェクト：資産収集 [ScopeSentry](https://github.com/Autumn-27/ScopeSentry)、承認 UI の参考 [AegisHook](https://github.com/RuoJi6/AegisHook)。

## 2. アーキテクチャ分解（リポジトリの一次情報より）

**技術スタック**：Go バックエンド（自作エージェント SDK **`Autumn-27/norma`**）＋ Next.js フロント内蔵の単一バイナリ、**PostgreSQL**（埋め込み SQLite も）。認証は JWT。

- **Planner / Worker ＋ 共有グラフ**（`agent/`）：
  - **計画役（planner）＝意図(intent)を生成する唯一の主体**、**実行役（worker）が意図を1件ずつ実行**して結果を書き戻す自動ループ（`blackboard_*`, `coldgraph`, `compaction`, `constraints`）。
  - **デュアルグラフ**：タスク横断で共有する**資産グラフ**と、タスクごとの進捗＝**探索グラフ**。
- **記録型プロキシ**（`traffic/`、依存 `lqqyt2423/go-mitmproxy`）：**通信を MITM プロキシ経由で記録**し、Agent が履歴トラフィックを検索・比較できる。**＝通信の単一チョークポイント**。
- **LLM 層**：`llmpool`（プロバイダのプール＋ヘルス方針）、`llmrec`（**LLM 呼び出しの記録**）。**Anthropic / OpenAI＋互換**に対応、プロバイダ/モデル/接続先は UI 設定。
- **MCP クライアント**（`mcphttp/`、SSE / Streamable HTTP）＝外部ツールの拡張口。
- **スキル機構**（`skills/`、各 `SKILL.md` のファイルベース＝Hermes 型）。同梱は **api-recon（API偵察）/ playwright-cli（ブラウザ自動操作）/ scopesentry（資産・スコープ連携）** の偵察・スコープ系（※本書は内容を転記しない）。
- **偵察ライブラリ**：ProjectDiscovery 系（`dnsx` / `cdncheck` / `blackrock`）、`miekg/dns`。
- **内蔵ガバナンス（注目）**：`guard/`（**承認ゲート：許可/拒否/確認**）、`intercept/`（**破壊的 API の deny ルール**。例：`/delete /del /remove /unlink /erase /destroy` を既定で遮断、「模型兜底審批」＝モデルによる兜底審査）、スコープ強制（`assets_scope` / `asset_intercept` / `intercept_filter` / `orchestration`）、`evidence/`（証跡）、`selfupdate/`（自動更新）。

## 3. Strix / Cairn / Hermes との比較

- **アーキ的に Cairn に最も近い**：planner/worker ＋共有の意図・資産グラフ（＝Cairn の blackboard/fact-intent グラフ）。
- **Hermes 型のスキル機構**（`SKILL.md` のファイルベース拡張）を併せ持つ。
- **MCP で外部ツールを束ねる基盤型**（§6 の⑤）要素もあり＝**ハイブリッド**。
- **際立つ違い＝内蔵ガバナンスの厚さ**：承認ゲート・破壊的操作の deny・スコープ強制・LLM 記録を**ツール自身が持つ**。Strix/Cairn/Hermes より“統制つき”。

## 4. 防御観測点 → R1–R7 / G1–G6 対応

| ARTEX の構成・挙動 | 観測点 | 本リポの検知 |
|---|---|---|
| LLM 呼び出し（Anthropic/OpenAI/互換、`llmpool`/`llmrec`） | サーバ系からの LLM egress | **R1**（ローカルLLMなら R7 に重心） |
| worker の多ツール連続実行・`norma`・MCP | 1 プロセス配下の多種ツール集中 | **R7** |
| Kali/ツール・Docker 実行 | 特権/コンテナ起動 | **R2** |
| 偵察スキル・ProjectDiscovery・DNS 列挙 | 偵察バースト | **R3**（＋Web 4xx 集約） |
| 記録型 MITM プロキシ（`traffic/`） | 全通信の単一経路 | **R1/R4（egress）・R3** が観測しやすい急所 |
| メッセージング/外部通知（`notify/`） | C2 的チャネル | **R4** |
| スキル機構（`SKILL.md`）の安全機構回避的利用 | ガバナンス兆候 | **T1562 相当・G1–G6** |
| **ARTEX 内蔵の承認/拦截/スコープ/LLM記録** | 正規運用時の監査点 | **G1–G6**（承認・監査・権限・ログ） |

**要点**：記録型プロキシと単一プランナーは、攻撃側にとっての効率化だが、**守る側には“集約された観測点／急所”**になる。ARTEX 自身の承認ゲート・deny ルール・スコープ強制・LLM 記録は、「攻撃エージェントを**自組織で正規運用**する側」が **G1–G6** で押さえるべき項目の雛形でもある。

## 5. 未確認の主張（鵜呑み禁止）

- **韓国・金融機関（新韓銀行関連）の侵害に ARTEX の痕跡**（Web サーバの HTML タイトルに `ARTEX-自主渗透测试控制台`、DeepSeek 連携）との報道 → **“疑い・手がかり”段階で未確定**。
- 中文コミュニティの**「ゼロ人手で 0day 発見」**（金蝶/Kingdee）→ **未検証の転述**。

## 6. 出典

- 本家リポジトリ（AGPL-3.0）: https://github.com/Autumn-27/ARTEX （静的レビュー）／英語UI版フォーク: https://github.com/hongvincent/ARTEX
- 解説（国内）: https://piyolog.hatenadiary.jp/ の「ARTEX とは」
- 解説（英語）: https://zendot.org/en/posts/autumn-27-artex
- 報道（未確定）: SBS / Seoul Economic Daily / BigGo（韓国・金融機関関連）

> 本書は検知・防御の設計に限定。攻撃の実行手順・兵器化・安全機構の回避方法は含まない。
