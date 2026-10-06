# 3ツール横断 防御・検知ノート（Strix / Cairn / Hermes）

Gambit レポートの攻撃連鎖（偵察→侵入→統括/事後）を、**防御側の観測点と対策**に振って整理したもの。
攻撃手順のレシピではなく、「何が観測され、どこで止められるか」に焦点を当てる。

出典: [Gambit Security](https://gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company) /
各ツール: [Strix](https://github.com/usestrix/strix) / [Cairn](https://github.com/oritera/Cairn) / [Hermes](https://github.com/NousResearch/hermes-agent)

---

## 攻撃連鎖の役割分担（本セッションの解析より）

| 段階 | ツール | やること | 技術的特徴 |
|---|---|---|---|
| 偵察・スキャン | **Strix** | 攻撃面の発見・脆弱性探索 | Docker サンドボックスで実行、caido プロキシで HTTP 捕捉、nmap/ffuf/playwright 等を同梱 |
| 探索的侵入 | **Cairn** | 目標（shell/flag）まで自走探索 | 黒板サーバ(:8000)＋fact-intent グラフ、OODA ワーカーを per-project コンテナで起動（NET_RAW/NET_ADMIN） |
| 統括・事後 | **Hermes** | キャンペーン統括・事後作業 | 汎用エージェント、多数のスキル、Telegram/Discord/Slack ゲートウェイ、cron、サブエージェント、7 実行バックエンド |

共通の土台: **LLM API への継続的な egress**（レポートでは OpenRouter 経由、Claude/DeepSeek 等）。これが 3 ツール共通の最も安定した観測点。

---

## 段階別：観測できる兆候 → 防御/検知

### A. 偵察・スキャン（Strix 的挙動）
観測点:
- 単一ソースからの**広域ポート/パス走査**、短時間の多数リクエスト、既知スキャナの UA/挙動。
- 送信元が **自動化ブラウザ（playwright/CDP）** 由来のフィンガープリント。
- 外向きに **LLM API への定期的・バースト的 HTTPS**（スキャン判断のたびに推論）。

防御/検知:
- WAF/レート制限、スキャン検知（多数 404/403・パス列挙）、ボット対策。
- 管理画面・機微エンドポイントの**認証必須化＋IP 制限/VPN 内側**（`netcheck` が「管理画面 URL の応答」を確認対象にしているのと表裏）。
- セキュリティヘッダ整備（CSP/HSTS/XFO/nosniff）。決済ページの **CSP は skimmer 注入対策の要**。

### B. 探索的侵入（Cairn 的挙動）
観測点:
- 内部に **黒板サーバ(:8000 / FastAPI)** と、**per-project ワーカーコンテナ**が多数起動（イメージ名 `cairn-worker-container`、`NET_RAW/NET_ADMIN` 付与）。
- ワーカーからの**反復的な試行→観測→再試行**パターン（OODA。失敗しても別 intent で粘る）。
- 継続的な **LLM API egress** と、対象への断続的なプローブ。

防御/検知:
- EDR/コンテナランタイム監視: **NET_RAW/NET_ADMIN 付きコンテナの新規起動**、未知イメージの pull、`host` ネットワークモードのコンテナを警戒。
- 内部セグメンテーション（lateral movement 阻止）、重要資産への最小権限・多要素。
- 送信ドメイン allowlist（LLM API への常時 egress は正規業務でなければ異常）。

### C. 統括・事後（Hermes 的挙動）
観測点:
- **メッセージングアプリ（Telegram/Discord/Slack/Signal）への外向き接続**＝ C2 的チャネルになり得る。
- **cron/スケジューラによる永続化**、サブエージェントの大量スポーン、スキルの動的生成/自己改変。
- 「**自身の安全フィルタを外す**」類のスキル追加（Gambit が 78/121 の攻撃スキル、うちフィルタ除去を指摘）。

防御/検知:
- 外向きメッセージング API への接続監視（サーバ/本番ホストからの Telegram 等は強い異常シグナル）。
- 永続化監視（新規 cron/サービス/スタートアップ項目）、プロセス系統の異常（自動化された連続ツール実行）。
- LLM 利用ガバナンス: **安全機構の除去・迂回を図る挙動**は方針・契約・CVP の不変の一線（物理被害/大規模妨害/ランサム/安全系無効化はブロック）に照らして遮断・通報。

---

## 横断的な「効く」対策（優先順）

1. **外向き通信の allowlist** — LLM API・メッセージングへの常時 egress は最強の共通シグナル。本番/サーバ系からの当該通信を既定で遮断・監視。
2. **コンテナ/実行環境の可視化** — 特権 cap 付きコンテナ、未知イメージ、host ネットの起動を検知。
3. **攻撃面の最小化** — 管理画面の隔離、DB/サービスをネット直結にしない（`netcheck` の RISKY ポート群が示す露出を塞ぐ）。
4. **決済・機微ページの CSP** — skimmer/カード窃取コード注入の防止。
5. **永続化・自動化の監視** — cron/スケジュール、連続自動ツール実行、サブエージェント大量生成。
6. **ログと相関** — スキャン痕跡＋LLM egress＋特権コンテナ＋外向きメッセージングを**時系列で相関**させると、単発では見えない「自律エージェント攻撃」が像を結ぶ。

---

## 本リポジトリ資産との対応

- `netcheck/`: A の露出面（RISKY ポート、ヘッダ、管理画面応答）を**自分の資産で確認**するための道具。
- `vuln_triage.html` / `scripts/summarize.py`: スキャナ結果を集約し、A/B の修正優先度付け。
- `security-scan.yml`（Semgrep/Trivy/gitleaks）: コード/依存/シークレットの事前防御。
- `cvp-readiness.md`: これらを CVP（Defense/Red Team）の統制証拠として束ねる枠組み。

> 本ノートは防御・検知の観点に限定し、攻撃の再現手順や安全機構の回避方法は含めない。
