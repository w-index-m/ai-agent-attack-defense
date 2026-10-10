# Cyber Verification Program 申請パッケージ

*ai-agent-attack-defense — 防御研究・統制証拠一式 ／ 2026-10-10 更新*


**プロジェクト**: `ai-agent-attack-defense`（w-index-m）

**目的**: Gambit Security レポート（2026-09-22）の AI エージェント攻撃（Strix / Cairn / Hermes）を題材にした
防御研究と小ツール群。本パッケージは Anthropic [Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program)
（公式ページ公開日 2026-10-06）の申請時に提示する「統制・責任ある取り扱い・技術的検証能力」の証拠を 1 冊に束ねたもの。

## 申請サマリ

- **想定ティア**:
  - 防御研究 → **Defense Access**（個人は公式条件の「報告済み脆弱性の実績」を別途示す）
  - 組織として認可ラボでの攻撃的テスト → **Red Team Access**（組織のみ）
- **責任ある取り扱い**: 対象は所有/認可物に限定（README・SECURITY.md・CONTRIBUTING.md に明記、MIT）。netcheck は範囲外を実行前拒否・同意必須・実行ログ。
  攻撃ツールの解析は**静的レビューが中心**で、実行したのは攻撃を伴わない検証（Strix の LLM 非依存 PoC、Cairn の mock）のみ。攻撃レシピや安全機構の除去は作成・再構成しない方針を文書化。
- **隔離・運用統制**: 認可ラボ・ランブック、隔離ネットワーク設計、攻撃なし mock 検証（実機確認済み）。
- **技術的検証能力**: Strix のローカル実行 PoC、検知ルール（R1–R7）、定義の一元化と CI の整合性チェック。
- **データ保持**: モニタリングのためのデータ保持が必須であることを理解している。

## 収録ドキュメント

1. CVP 適用メモ＆ティア対応表（`cvp-readiness.md`）— 公式の記載（2026-10-06 公開）に合わせて更新
2. 3ツール横断 防御・検知ノート（`defense-detection-notes.md`）— 検知ルール R1–R7、MITRE ATT&CK 対応、トリアージ手順を含む
3. Cairn 認可ラボ・ランブック（`cairn-lab/cairn-authorized-lab-runbook.md`）
4. Strix ローカル実行バックエンド設計・PoC（`strix-local-backend-notes.md`）

**付随リソース（本冊子には全文は載せず、リポジトリに収録）**:

- `security-scan/detections/` — R1–R7 の実スタック向けルール（Sigma / Falco / Datadog / Elastic）。
- `security-scan/artex-analysis.*` — ARTEX の防御解析（静的レビューのみ）。
- `security-scan/zgrab2-notes.md` — スキャナ出力の取り込みと、対象を許可範囲に絞るガード（`scripts/zgrab2_guard.py`）。

> 本パッケージは防御・統制の観点に限定し、攻撃の再現手順や安全機構の回避方法は含まない。

---
