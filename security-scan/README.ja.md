# security-scan — 日本語インデックス

Gambit Security レポート（2026-09-22）の AI エージェント攻撃（Strix / Cairn / Hermes）を題材にした
**防御研究・検知・統制**の一式。本ディレクトリの入口（日本語）。
**検知・防御の設計に限定**し、攻撃の実行手順や安全機構の回避方法は含めない。対象は所有/認可物のみ。

## まず見るもの

- **[`dashboard.html`](dashboard.html)** — 統合ダッシュボード（ブラウザで開くだけ・オフライン・外部通信なし）。
  攻撃エージェントの俯瞰 → 検知カバレッジ → 予防コントロール → CVP 対応 → 資産リンクを 1 枚で。
- **[`dashboard-local-llm.html`](dashboard-local-llm.html)** — 上記＋「AIに質問」を**自前の LLM**（ローカルの Ollama/LM Studio、または OpenAI 互換エンドポイント）で動かすローカル版。claude.ai のクオータ不要。接続設定はブラウザに保存、通信は指定した LLM のみ。file:// から叩くため CORS 許可が必要（Ollama: `OLLAMA_ORIGINS=*` 等）。

## ドキュメント

| ファイル | 内容 |
|---|---|
| [`defense-detection-notes.md`](defense-detection-notes.md) | 3ツール横断の防御・検知ノート。SOC 運用レイヤー（データソース対応、検知ルール R1–R7、MITRE ATT&CK、トリアージ）と、攻撃用AIエージェントの広域マップ（§6）。 |
| [`defense-playbook.ja.md`](defense-playbook.ja.md) / [`.en.md`](defense-playbook.en.md) | **AI エージェント攻撃 防御プレイブック**。Strix / Cairn / Hermes / ARTEX の見える動きを前提に、攻撃連鎖の7段ごとの予防・検知・応答・確認、インシデント対応、罠（ハニートークン）の設計メモ、最初の1週間、**未実装の一覧**。 |
| [`defense-layers-and-roadmap.md`](defense-layers-and-roadmap.md) | 防御の4層（予防・検知・応答・復旧）と、外部ロードマップ案の対応づけ・評価・不足分の補い方。R1–R7 と ③ の区別、カーネルFIM 解説つき。 |
| [`glossary.ja.md`](glossary.ja.md) | 用語集（やさしい日本語）。FIM / CSP / WORM / egress / C2 / RCE / IAM などを1行ずつ。新語が出たら追記する。 |
| [`os-patch-check-notes.md`](os-patch-check-notes.md) | 自分の機器の OS 更新を確認し、SARIF で `vuln_triage` に読み込む。**Linux(RHEL系)用 `scripts/os_patch_check_linux.py`** と **Windows用 `scripts/os_patch_check_windows.py`** に分けている。確認専用。実機では未検証。 |
| [`patch-suggest-notes.md`](patch-suggest-notes.md) | 診断結果から修正案（diff）を作る `scripts/patch_suggest.py`。自動適用はしない（人の y/N 確認つき）。gitleaks の値は LLM に送らない。小さいモデルの限界を明記。 |
| [`zgrab2-notes.md`](zgrab2-notes.md) | zgrab2（ZMap のアプリ層スキャナ）の出力を `vuln_triage` に取り込む方法と、対象を許可範囲に絞るガード `scripts/zgrab2_guard.py`。露出の棚卸し用で、脆弱性スキャナではない。日英。 |
| [`artex-analysis.ja.md`](artex-analysis.ja.md) / [`.en.md`](artex-analysis.en.md) | 自律型ペネトレ AI エージェント **ARTEX** の防御解析（一次情報の静的レビュー）。アーキ分解＋R1–R7/G1–G6 対応。攻撃手順は含まない。 |
| [`detections/`](detections/) | 検知ルールの実装：Sigma / Falco / Datadog（R1–R7）。閾値・allowlist は環境でチューニング。 |
| [`strix-local-backend-notes.md`](strix-local-backend-notes.md) | Strix の実行フロー解析と、Docker 不要ローカル実行の設計。 |
| [`strix-local-poc/`](strix-local-poc/) | 上記の PoC（パッチ・検証スクリプト・結果）。 |
| [`cairn-lab/`](cairn-lab/) | Cairn を認可済み隔離ラボで動かすランブックと実設定（`dispatch.lab.yaml` ほか）、攻撃なし mock 設定。 |
| [`cvp-application-form-draft.md`](cvp-application-form-draft.md) | CVP 申請フォームの下書き（Defense Access）。提出前チェック、各項目の回答案（英語＋日本語の意味）、書いてはいけない例。**実績など本人にしか書けない項目は空欄**。 |
| [`cvp-readiness.md`](cvp-readiness.md) | Anthropic Cyber Verification Program のティア対応と申請準備。 |
| [`sandbox-defense-model.ja.md`](sandbox-defense-model.ja.md) / [`.en.md`](sandbox-defense-model.en.md) | サンドボックス防御モデル（スキャンパターン別・使い捨ての正体）。実スキャンなしの防御解説。 |
| [`cvp-package/`](cvp-package/) | 申請パッケージ（HTML / PDF）。`python3 security-scan/cvp-package/build_package.py` で元の文書から再生成できる（pandoc と Chromium が必要）。 |

## 検知ルール早見（優先度順）

1. **R1 / R4** — サーバ系からの LLM / メッセージング API egress（最優先）
2. **R2** — 特権 / host net / 未知イメージのコンテナ起動
3. **R7** — 1 親プロセスが多種ツールを短時間連続実行（**ローカルLLM型でも残る核**）
4. **R3** — 偵察的 Web 列挙バースト
5. **R5** — 永続化（cron / systemd）の新規作成
6. **R6** — 上記を束ねる相関（単発では見えない連鎖を検知）

## 言語について

- 本リポの解説・ノート・ランブックは日本語。ダッシュボードは日英併記。
- `detections/` の Sigma/Falco/Datadog ルールは、SIEM への移植性のため**説明文を英語**にしている
  （各ルールの意味は本 README と `defense-detection-notes.md`・`detections/README.md` に日本語で記載）。
- 英語版ドキュメントが必要な場合は別途作成可能。
