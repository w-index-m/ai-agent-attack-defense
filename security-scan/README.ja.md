# security-scan — 日本語インデックス

Gambit Security レポート（2026-09-22）の AI エージェント攻撃（Strix / Cairn / Hermes）を題材にした
**防御研究・検知・統制**の一式。本ディレクトリの入口（日本語）。
**検知・防御の設計に限定**し、攻撃の実行手順や安全機構の回避方法は含めない。対象は所有/認可物のみ。

## まず見るもの

- **[`dashboard.html`](dashboard.html)** — 統合ダッシュボード（ブラウザで開くだけ・オフライン・外部通信なし）。
  攻撃エージェントの俯瞰 → 検知カバレッジ → 予防コントロール → CVP 対応 → 資産リンクを 1 枚で。

## ドキュメント

| ファイル | 内容 |
|---|---|
| [`defense-detection-notes.md`](defense-detection-notes.md) | 3ツール横断の防御・検知ノート。SOC 運用レイヤー（データソース対応、検知ルール R1–R7、MITRE ATT&CK、トリアージ）と、攻撃用AIエージェントの広域マップ（§6）。 |
| [`detections/`](detections/) | 検知ルールの実装：Sigma / Falco / Datadog（R1–R7）。閾値・allowlist は環境でチューニング。 |
| [`strix-local-backend-notes.md`](strix-local-backend-notes.md) | Strix の実行フロー解析と、Docker 不要ローカル実行の設計。 |
| [`strix-local-poc/`](strix-local-poc/) | 上記の PoC（パッチ・検証スクリプト・結果）。 |
| [`cairn-lab/`](cairn-lab/) | Cairn を認可済み隔離ラボで動かすランブックと実設定（`dispatch.lab.yaml` ほか）、攻撃なし mock 設定。 |
| [`cvp-readiness.md`](cvp-readiness.md) | Anthropic Cyber Verification Program のティア対応と申請準備。 |
| [`cvp-package/`](cvp-package/) | 申請パッケージ（HTML / PDF）。 |

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
