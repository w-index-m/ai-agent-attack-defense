# Cyber Verification Program（CVP）適用メモ ＆ 申請準備

Anthropic の [Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program) に、本プロジェクト
（`ai-agent-attack-defense`: Gambit レポートの AI エージェント攻撃 Strix/Cairn/Hermes を題材にした**防御研究＋小ツール**）
をどう対応づけ、どのティアを申請するかを整理したもの。

> 出典ページの要点は末尾「参考」に記載。数値・制度内容は Anthropic の発表に基づく。

---

## 1. CVP 3 ティア（要約）

| ティア | 対象 | 許可範囲 | 申請主体 | 審査 |
|---|---|---|---|---|
| **Defense Access** | 防御（SOC・IR・マルウェア解析・脆弱性検証） | 防御業務向けの制限緩和 | 組織／**実績ある個人研究者も可** | 数日 |
| **Red Team Access** | 認可されたペンテスト・敵対的評価（重要インフラ IT 含む） | 認可済みシステムへの攻撃的テスト（物理被害・大規模妨害・ランサム・安全系無効化は常時ブロック） | **組織のみ** | 数週間 |
| **Specialized Access** | 安全重要システム（航空/電力/通信/金融/政府網）のテスト認可組織 | ほぼ最小制限 | 組織（**米政府連携が必要**） | — |

- 全ティアで Claude Opus 5.5 / Sonnet 5.5 / Mythos 5.1 等にアクセス。
- 申請は Anthropic ポータル。本人確認＋**必要なセキュリティ統制の証明**が要る。**データ保持モニタリング必須**（Enterprise Frontier Safeguards でゼロ保持オプション予定）。

---

## 2. 本プロジェクトの活動 → ティア対応表

| 活動（本リポジトリ） | 性質 | 対応ティア |
|---|---|---|
| `vuln_triage.html` / `scripts/summarize.py`（スキャン結果の集計・トリアージ） | 防御（脆弱性検証） | **Defense** |
| `netcheck/`（所有資産の確認専用チェック、確認だけ・攻撃なし） | 防御 | **Defense** |
| `.github/workflows/security-scan.yml`（Semgrep/Trivy/gitleaks CI） | 防御（コード/依存の検証） | **Defense** |
| Strix/Cairn/Hermes の**コード・アーキテクチャ解析**（`security-scan/*-notes.md`） | 防御（マルウェア/攻撃ツール解析） | **Defense** |
| Strix の**ローカル実行 PoC**（`strix-local-poc/`、良性コードへの静的解析） | 防御寄り／研究 | **Defense** |
| Cairn を**認可ラボで実際に走らせる**（`cairn-lab/` ランブック） | 攻撃的テスト | **Red Team**（組織のみ） |
| 安全重要システム（電力/通信等）への実テスト | 安全重要 | **Specialized**（該当時のみ・米政府連携） |

**読み方**: 現状の成果物の大半は **Defense** の射程。Cairn/Strix を認可ターゲットへ能動的に走らせる段になって初めて **Red Team**（組織申請）が必要。

---

## 3. 申請準備：本リポジトリが示せる「統制・実績」の証拠

CVP 申請では「必要なセキュリティ統制」と（個人 Defense では）脆弱性報告などの実績が問われる。現状の資産の対応：

- **責任ある取り扱いの実績**
  - README に「**自分が所有・認可した対象にのみ使用**」を明記。
  - `netcheck` は許可レンジ外を**実行前に拒否**／同意必須／ローカル限定トークン／実行ログ（`netcheck.log`）。
  - 攻撃ツール解析で**攻撃レシピや安全フィルタ除去の再構成は扱わない**方針を文書化（Hermes メモ）。
- **隔離・運用統制の設計**
  - `cairn-lab/cairn-authorized-lab-runbook.md`: 実行前チェックリスト、ネットワーク隔離、egress 制限、使い捨て/スナップショット、監視、禁止事項。
  - `cairn-lab/dispatch_mock_local.yaml`: **攻撃せずにエンジンのみ検証**した構成（本番前スモーク）。
- **技術的検証能力**
  - `strix-local-poc/`: バックエンド差し替え＋PoC（再現手順・パッチ・検証ログ）。
- **（任意）秘密情報管理**: `.gitleaks.toml` / `.pre-commit-config.yaml` によるシークレット検出。

> 申請時は上記を「統制の証明」資料として束ねられる。秘密情報（LLM キー等）はコミットしない運用を継続する。

---

## 4. 推奨アクション

1. **個人で始めるなら → Defense Access を申請**（審査は数日）。
   - 申請材料: 本リポジトリ（防御ツール＋解析ノート＋責任ある取り扱いの記録）。
   - 期待効果: 脆弱性検証・攻撃ツール解析の精度向上。
2. **組織として本番ペンテストまで行うなら → Red Team Access**（組織申請・数週間）。
   - 申請材料: §3 の隔離設計・ランブック・mock 検証を「統制の証明」として提出。
   - 前提: 対象の所有/書面認可、隔離ラボ、データ保持要件の充足。
3. **不変の一線**: Red Team でも物理被害・大規模妨害・ランサム・安全系無効化はブロック対象。本プロジェクトの方針（攻撃レシピ・安全フィルタ除去を作らない）と整合。

---

## 参考

- [Anthropic — Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program)
  - Project Glasswing と旧 CVP を統合した拡張枠組み。
  - Glasswing 実績: 2026/4–7 に 12.9 万件以上の検証済み脆弱性（うち 3.3 万件超が critical/high）。
  - CyScenarioBench: Defense は悪性多段攻撃 50 件中 46 件をブロック／Red Team は 50 件中 34 件を無制限時と同等に完遂。
