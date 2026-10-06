---
title: "Cyber Verification Program 申請パッケージ"
subtitle: "ai-agent-attack-defense — 防御研究・統制証拠一式"
date: "2026-10-06"
---

# Cyber Verification Program 申請パッケージ

**プロジェクト**: `ai-agent-attack-defense`（w-index-m）
**目的**: Gambit Security レポート（2026-09-22）の AI エージェント攻撃（Strix / Cairn / Hermes）を題材にした
防御研究と小ツール群。本パッケージは Anthropic [Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program)
申請時に提示する「統制・責任ある取り扱い・技術的検証能力」の証拠を 1 冊に束ねたもの。

## 申請サマリ

- **想定ティア**:
  - 個人の防御研究 → **Defense Access**
  - 組織として認可ラボでの攻撃的テスト → **Red Team Access**
- **責任ある取り扱い**: 対象は所有/認可物に限定（README 明記）。netcheck は範囲外を実行前拒否・同意必須・実行ログ。
  攻撃レシピや安全機構の除去は作成・再構成しない方針を文書化。
- **隔離・運用統制**: 認可ラボ・ランブック、隔離ネットワーク設計、攻撃なし mock 検証（実機確認済み）。
- **技術的検証能力**: Strix のローカル実行 PoC（再現手順・パッチ・検証ログ）。

## 収録ドキュメント

1. CVP 適用メモ＆ティア対応表（`cvp-readiness.md`）
2. 3ツール横断 防御・検知ノート（`defense-detection-notes.md`）
3. Cairn 認可ラボ・ランブック（`cairn-lab/cairn-authorized-lab-runbook.md`）
4. Strix ローカル実行バックエンド設計・PoC（`strix-local-backend-notes.md`）

> 本パッケージは防御・統制の観点に限定し、攻撃の再現手順や安全機構の回避方法は含まない。

---
