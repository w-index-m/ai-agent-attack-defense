# security-scan — 日本語インデックス

Gambit Security レポート（2026-09-22）の AI エージェント攻撃（Strix / Cairn / Hermes）を題材にした
**防御研究・検知・統制**の一式。本ディレクトリの入口（日本語）。
**検知・防御の設計に限定**し、攻撃の実行手順や安全機構の回避方法は含めない。対象は所有/認可物のみ。

## まず見るもの

- **[`dashboard.html`](dashboard.html)** — 統合ダッシュボード（ブラウザで開くだけ・オフライン・外部通信なし）。
  攻撃エージェントの俯瞰 → 検知カバレッジ → 予防コントロール → CVP 対応 → 資産リンクを 1 枚で。
- **[`dashboard-local-llm.html`](dashboard-local-llm.html)** — 上記＋「AIに質問」を**自前の LLM**（ローカルの Ollama/LM Studio、または OpenAI 互換エンドポイント）で動かすローカル版。claude.ai のクオータ不要。接続設定はブラウザに保存、通信は指定した LLM のみ。file:// から叩くため CORS 許可が必要（Ollama: `OLLAMA_ORIGINS=*` 等）。

## ドキュメント

全体で25件超になったため、テーマ別に分けている。横断的な索引（検知タグ R1–R11・G1–G6の正式な定義）は [`../shared/taxonomy.json`](../shared/taxonomy.json)。

### 全体像・サマリー

| ファイル | 内容 |
|---|---|
| [`security-summary.ja.md`](security-summary.ja.md) / [`.en.md`](security-summary.en.md) | **セキュリティ問題のまとめ**。攻撃の7段と対応、既知の脆弱性、企業が取るべき対応、作ったもの、検証の状態（正直に）、次にやること。まずここから読む。 |
| [`defense-playbook.ja.md`](defense-playbook.ja.md) / [`.en.md`](defense-playbook.en.md) | **AI エージェント攻撃 防御プレイブック**。Strix / Cairn / Hermes / ARTEX の見える動きを前提に、攻撃連鎖の7段ごとの予防・検知・応答・確認、インシデント対応、罠（ハニートークン）の設計メモ、最初の1週間、**未実装の一覧**。 |
| [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md) | 防御の4層（予防・検知・応答・復旧）と、外部ロードマップ案の対応づけ・評価・不足分の補い方。R1–R8 と ③ の区別、カーネルFIM 解説つき。 |
| [`glossary.ja.md`](glossary.ja.md) | 用語集（やさしい日本語）。FIM / CSP / WORM / egress / C2 / RCE / IAM などを1行ずつ。新語が出たら追記する。 |

### AIエージェントが攻撃する側（Gambit系：Strix / Cairn / Hermes / ARTEX）

| ファイル | 内容 |
|---|---|
| [`defense-detection-notes.md`](defense-detection-notes.md) | 3ツール横断の防御・検知ノート。SOC 運用レイヤー（データソース対応、検知ルール R1–R8、MITRE ATT&CK、トリアージ）と、攻撃用AIエージェントの広域マップ（§6）。 |
| [`artex-analysis.ja.md`](artex-analysis.ja.md) / [`.en.md`](artex-analysis.en.md) | 自律型ペネトレ AI エージェント **ARTEX** の防御解析（一次情報の静的レビュー）。アーキ分解＋R1–R8/G1–G6 対応。攻撃手順は含まない。 |
| [`unit42-ai-assisted-intrusion.ja.md`](unit42-ai-assisted-intrusion.ja.md) / [`.en.md`](unit42-ai-assisted-intrusion.en.md) | Unit 42 の実インシデント報告「AI支援サイバー攻撃」の分析。人間の攻撃者が frontier AI エージェントで侵入を自動化し、2週間相当の作業を10時間未満で完了。MITRE ATT&CK×ATLAS対応表、R1–R8/G1–G6 との接続点つき。 |
| [`jp-advisory-mapping.ja.md`](jp-advisory-mapping.ja.md) / [`.en.md`](jp-advisory-mapping.en.md) | **国内の注意喚起（2026年10月、JPCERT/CC・個人情報保護委員会など）と、このリポジトリの対応表**。API の不正操作、既知の脆弱性（BI ツールを含む）、管理不備、Web シェルの 4 つの型ごとに、予防・検知・足りない点を整理。二次情報に基づくので、原典で確認すること。 |
| [`fortimanager-peerstitch-notes.ja.md`](fortimanager-peerstitch-notes.ja.md) / [`.en.md`](fortimanager-peerstitch-notes.en.md) | **【AI関与なし】** Unit 42 の実インシデント報告「PEERSTITCH」の分析。FortiManagerの脆弱性（CVE-2024-47575）から500台超のFortiGateへ波及した侵害と、メモリ常駐型インプラントの技術解説。Gambit連鎖⑥（過剰な権限）との接続点つき。AIが関与しない対照事例として収録。 |
| [`strix-local-backend-notes.md`](strix-local-backend-notes.md) | Strix の実行フロー解析と、Docker 不要ローカル実行の設計。 |
| [`strix-local-poc/`](strix-local-poc/) | 上記の PoC（パッチ・検証スクリプト・結果）。 |
| [`cairn-lab/`](cairn-lab/) | Cairn を認可済み隔離ラボで動かすランブックと実設定（`dispatch.lab.yaml` ほか）、攻撃なし mock 設定。 |

### 【スコープ拡張】LLMシステムが標的になる側

| ファイル | 内容 |
|---|---|
| [`llm-target-attacks.ja.md`](llm-target-attacks.ja.md) / [`.en.md`](llm-target-attacks.en.md) | **LLM システム自体への攻撃**（プロンプトインジェクション、システムプロンプト漏洩、間接的プロンプトインジェクション、LLMjacking、**マルチエージェント間のセッション悪用**の5類型）の、一次情報に基づく整理。既存の R1–R8/G1–G6 との接続点つき（C・D・EはR9–R11として実装済み）。Unit 42 の CrewAI/AutoGen 実証研究・Web経由IDPIの大規模実態調査・GCP Vertex AI "Double Agents"・Agent Session Smuggling（A2Aプロトコル）も収録。 |
| [`openclaw-skill-supply-chain.ja.md`](openclaw-skill-supply-chain.ja.md) / [`.en.md`](openclaw-skill-supply-chain.en.md) | AIエージェント **OpenClaw** のスキル・マーケットプレイス **ClawHub** を舞台にした、Unit 42 の2本の一次情報の整理。悪性スキルの実例（情報窃取・スキャン回避・エージェント特有の金銭目的型）と、振る舞い整合性検証（BIV）によるレジストリ全体調査（49,943件中80%に乖離）。 |
| [`llm-defense-checklist.ja.md`](llm-defense-checklist.ja.md) / [`.en.md`](llm-defense-checklist.en.md) | `llm-target-attacks.ja.md` の5類型の予防・検知項目を、**自分のシステムで守られているか確認するチェックリスト**にしたもの。自動判定スクリプトではなく、人が確認する前提。 |

### 検知ルールの実装

| ファイル | 内容 |
|---|---|
| [`detections/`](detections/) | 検知ルールの実装：Sigma / Falco / Datadog（R1–R8、Gambit系）＋Sigma / Datadog（R9–R11、LLM標的攻撃のパターンC・D・E）。閾値・allowlist は環境でチューニング。 |

### 自分の環境を確認するツール

| ファイル | 内容 |
|---|---|
| [`os-patch-check-notes.md`](os-patch-check-notes.md) | 自分の機器の OS 更新を確認し、SARIF で `vuln_triage` に読み込む。**Linux(RHEL系)用 `scripts/os_patch_check_linux.py`** と **Windows用 `scripts/os_patch_check_windows.py`** に分けている。確認専用。実機では未検証。 |
| [`patch-suggest-notes.md`](patch-suggest-notes.md) | 診断結果から修正案（diff）を作る `scripts/patch_suggest.py`。自動適用はしない（人の y/N 確認つき）。gitleaks の値は LLM に送らない。小さいモデルの限界を明記。 |
| [`zgrab2-notes.md`](zgrab2-notes.md) | zgrab2（ZMap のアプリ層スキャナ）の出力を `vuln_triage` に取り込む方法と、対象を許可範囲に絞るガード `scripts/zgrab2_guard.py`。露出の棚卸し用で、脆弱性スキャナではない。日英。 |
| [`dep-cve-check-notes.md`](dep-cve-check-notes.md) | `scripts/dep_cve_check.py`: `requirements.txt`（pip、`==` 固定行）と npm の `package-lock.json` を、公開の脆弱性データベース OSV.dev に照合する。出力は SARIF で `vuln_triage` にそのまま読み込める。モックで検証済み、実際の OSV API は未確認。日英。 |
| [`ghsa-lookup-notes.md`](ghsa-lookup-notes.md) | `scripts/ghsa_lookup.py`: GHSA ID・CVE 番号から GitHub の公開 Advisories API の構造化データ（影響版・修正版・CWE・CVSS）を取得し、**要約せずそのまま** Markdown に転記する。2つの CVE を取り違えた過去の誤りの再発防止。モックで検証済み、実際の API はこのセッションの GitHub 連携の制約で未確認。日英。 |

### CVP（Cyber Verification Program）対応

| ファイル | 内容 |
|---|---|
| [`cvp-application-form-draft.md`](cvp-application-form-draft.md) | CVP 申請フォームの下書き（Defense Access）。提出前チェック、各項目の回答案（英語＋日本語の意味）、書いてはいけない例。**実績など本人にしか書けない項目は空欄**。 |
| [`cvp-readiness.md`](cvp-readiness.md) | Anthropic Cyber Verification Program のティア対応と申請準備。 |
| [`cvp-package/`](cvp-package/) | 申請パッケージ（HTML / PDF）。`python3 security-scan/cvp-package/build_package.py` で元の文書から再生成できる（pandoc と Chromium が必要）。 |

### その他

| ファイル | 内容 |
|---|---|
| [`sandbox-defense-model.ja.md`](sandbox-defense-model.ja.md) / [`.en.md`](sandbox-defense-model.en.md) | サンドボックス防御モデル（スキャンパターン別・使い捨ての正体）。実スキャンなしの防御解説。 |

## 検知ルール早見（優先度順）

**Gambit系（攻撃用AIエージェント、R1–R8）**

1. **R1 / R4** — サーバ系からの LLM / メッセージング API egress（最優先）
2. **R2** — 特権 / host net / 未知イメージのコンテナ起動
3. **R7** — 1 親プロセスが多種ツールを短時間連続実行（**ローカルLLM型でも残る核**）
4. **R3** — 偵察的 Web 列挙バースト
5. **R5** — 永続化（cron / systemd）の新規作成
6. **R6** — 上記を束ねる相関（単発では見えない連鎖を検知）

**LLM標的攻撃系（R9–R11、`llm-target-attacks.ja.md`のパターンC・D・E）**

- **R9** — LLM/エージェントの、許可リスト外ドメインへの指示誘導による送信（IDPIの兆候）
- **R10** — AIワークロードからのクラウドメタデータサービス資格情報エンドポイントへのアクセス
- **R11** — マルチエージェントのセッション内で、ユーザーの直接指示のないツール呼び出し（要アプリ計装）

## 言語について

- 本リポの解説・ノート・ランブックは日本語。ダッシュボードは日英併記。
- `detections/` の Sigma/Falco/Datadog ルールは、SIEM への移植性のため**説明文を英語**にしている
  （各ルールの意味は本 README と `defense-detection-notes.md`・`detections/README.md` に日本語で記載）。
- 英語版ドキュメントが必要な場合は別途作成可能。
