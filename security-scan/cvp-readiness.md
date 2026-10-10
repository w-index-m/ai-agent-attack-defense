# Cyber Verification Program（CVP）適用メモ ＆ 申請準備

English: [`cvp-readiness.en.md`](cvp-readiness.en.md)

Anthropic の [Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program)
（CVP = サイバー検証プログラム）に、本プロジェクト
（`ai-agent-attack-defense`: Gambit レポートの AI エージェント攻撃 Strix/Cairn/Hermes を題材にした**防御研究＋小ツール**）
をどう対応づけ、どのティアを申請するかを整理したもの。

> **出典と鮮度**: 公式ページ（公開日 2026-10-06）を **2026-10-10** に確認して反映した。制度は更新されうるので、
> 申請前に必ず公式ページで再確認すること。公式に書かれていない点は「記載なし」と明記し、推測で埋めない。

---

## 1. CVP 3 ティア（公式の記載）

| ティア | 対象 | 許可範囲 | 申請主体 | 審査 |
|---|---|---|---|---|
| **Defense Access** | 防御（SOC・インシデント対応・マルウェアのリバースエンジニアリング・脆弱性の分析/検証） | 防御業務向けに、ブロックの分類器を緩める | **組織**（企業・NPO・大学・政府の防御チーム、重要インフラ事業者、小規模セキュリティ企業、OSS メンテナ）と、**「報告済み脆弱性の実績」のある個人研究者** | 数日を目標 |
| **Red Team Access** | 認可されたペンテスト・レッドチーム（Defense の全てを含む） | **組織が認可を受けた対象に限る**。物理的被害・大規模な妨害につながる行為（ランサムウェアの展開、物理システムの破壊、**高リスクな安全系システムへのペンテスト**など）は引き続きブロック | **組織のみ**（社内レッドチーム、政府レッドチーム、ペンテスト会社）。**個人は不可** | 数週間。**審査中は Defense Access に登録される** |
| **Specialized Access** | 人命や市場に影響しうる安全重要システム（航空機の OS、電力網、通信網、銀行間送金、政府の行政網など）をテストする認可を受けた、限られた検証済み組織 | サイバー分野のブロックが最も少ない | 組織（全組織を**米政府と連携して詳細に審査**） | 記載なし |

### 共通事項
- **モデル**: 全ティアで Claude Opus 5.5 / Sonnet 5.5 / Mythos 5.1 と今後のモデルを利用可能。
- **一般提供モデルでもできること**: 一般提供モデル（Opus 5.5 / Fable 5.1 / Sonnet 5.5）は、サイバー作業の多くを保守的にブロックする。
  ただし、**コードレビュー、既知の問題のパッチ適用、自分のソースコードの脆弱性発見、セキュリティアラートのトリアージ**には引き続き使える。
  → これらは **CVP なしでも可能**。
- **申請**: ポータル https://portal.anthropic.com/programs/cvp 。**全申請者が検証**され、**ティアに必要なセキュリティ統制の証明**を求められる
  （具体的な書類は公式に記載なし）。
- **データ保持**: 登録組織は、サイバー悪用の監視のため**データ保持が必須**。
  Enterprise Frontier Safeguards（EFS: ゼロ保持＋防護、データを利用者管理のクラウドに置ける）は**「今秋後半」予定**。
  それまでは、Fable 5.1 / Mythos 5.1 の**ゼロ保持アクセスを持つ組織は、CVP もゼロ保持で利用可**。EFS の関心登録: https://claude.com/form/enterprise-frontier-safeguards
- **提供基盤**: Claude Platform / Google Cloud Vertex AI / Microsoft Foundry。Amazon Bedrock は EFS の対象顧客のみ。
- **既存メンバー**: 既存の CVP メンバーは従来のモデルの設定を維持し、新モデルは自動で評価される。Project Glasswing の既存メンバーは Specialized Access に移行（現行モデルは再承認不要）。
- **ワークスペース**: 管理者が、アクセスを割り当てるワークスペースを指定する（手順: [Claude Console のサポート記事](https://support.claude.com/en/articles/16764810-assign-a-program-to-workspaces-in-claude-console)）。
- **誤ブロック／却下の異議申立て**: https://claude.com/form/cyber-block-false-positive-report-cvp-rejection-appeal

---

## 2. 本プロジェクトの活動 → ティア対応表

| 活動（本リポジトリ） | 性質 | 対応ティア |
|---|---|---|
| `vuln_triage.html` / `scripts/summarize.py`（スキャン結果の集計・トリアージ。SARIF / netcheck / zgrab2 の取り込みを含む） | 防御（脆弱性の分析・検証） | **Defense** |
| `netcheck/`（所有資産の確認専用チェック、確認だけ・攻撃なし）、`scripts/zgrab2_guard.py`（スキャナに渡す対象を許可範囲に限定） | 防御 | **Defense** |
| `security-scan/detections/`（Sigma / Falco / Datadog / Elastic の検知ルール R1–R7） | 防御（検知の設計） | **Defense** |
| `.github/workflows/security-scan.yml`（Semgrep/Trivy/gitleaks CI）と、定義のズレを止める整合性チェック | 防御（コード/依存の検証） | **Defense** |
| Strix / Cairn / Hermes / ARTEX の**コード・アーキテクチャの静的解析**（`*-notes.md`, `artex-analysis.*`） | 防御（攻撃ツールの解析） | **Defense** |
| Strix の**ローカル実行 PoC**（`strix-local-poc/`、良性コードへの静的解析） | 防御寄り／研究 | **Defense** |
| Cairn を**認可ラボで実際に走らせる**（`cairn-lab/` ランブック） | 攻撃的テスト | **Red Team**（組織のみ） |
| 安全重要システム（電力/通信等）への実テスト | 安全重要 | **Specialized**（該当時のみ・米政府と連携） |

**読み方**: 現状の成果物の大半は **Defense** の射程。攻撃ツールを認可ターゲットへ**能動的に走らせる**段になって初めて **Red Team**（組織申請）が必要。

---

## 3. 申請準備：本リポジトリが示せるもの／示せないもの

CVP は「必要なセキュリティ統制の証明」を求める（具体書類は記載なし）。現状の資産で示せるもの：

- **責任ある取り扱い**
  - README・SECURITY.md・CONTRIBUTING.md に「**自分が所有・認可した対象にのみ使用**」「防御・検知の設計に限定」を明記。LICENSE は MIT。
  - `netcheck` は許可レンジ外を**実行前に拒否**／同意必須／ローカル限定トークン／実行ログ。`scripts/zgrab2_guard.py` も同じ判定を再利用し、範囲外が 1 つでも混ざれば**何も出力しない**。
  - 攻撃ツール解析は**静的レビューのみ（実行・ビルドしない）**で、攻撃レシピや安全フィルタ除去の再構成は扱わない方針を文書化（Hermes / ARTEX の解析に明記）。
- **隔離・運用統制の設計**
  - `cairn-lab/cairn-authorized-lab-runbook.md`: 実行前チェックリスト、ネットワーク隔離、egress 制限、使い捨て/スナップショット、監視、禁止事項。
  - `cairn-lab/dispatch_mock_local.yaml`: **攻撃せずにエンジンのみ検証**した構成。
- **技術的検証能力**
  - `strix-local-poc/`（再現手順・パッチ・検証ログ）、`detections/`（R1–R7）、`shared/taxonomy.json` ＋ CI の整合性チェック。
- **秘密情報管理**: `.gitleaks.toml` / `.pre-commit-config.yaml`。CI は緑。

**示せない／足りないもの（正直に）**

- **個人で Defense を申請する条件は「報告済み脆弱性の実績」**。本リポジトリは防御研究とツールであり、**脆弱性報告の実績の代わりにはならない**。
- 組織としての本人確認・組織の統制（Red Team の場合）。
- **データ保持とモニタリングを受け入れられるか**（機密・NDA 案件を扱う場合は要検討）。

> 秘密情報（LLM キー等）はコミットしない運用を継続する。

---

## 4. 推奨アクション

1. **まず「CVP なしで足りるか」を確認する。** コードレビュー、スキャン結果やアラートのトリアージ、自分のコードの脆弱性発見、防御ルールの作成は、
   公式上も一般提供モデルで可能。現状の作業の多くはこれに当たるので、**今すぐ必須ではない**。
2. **個人で Defense Access を目指す場合**: 条件は「報告済み脆弱性の実績」。実績がまだ無いなら、
   (a) 自分の資産／認可範囲／バグバウンティの範囲で、正規の脆弱性報告を行って実績をつくる、
   (b) 所属組織を通じて申請する、を検討する。本リポジトリは、**統制・責任ある取り扱い・技術力を示す補強材料**として添える（審査は数日を目標）。
3. **組織として認可ラボ／本番ペンテストまで行う場合 → Red Team Access**（組織申請・数週間、審査中は Defense に登録）。
   前提: 対象の所有/書面認可、隔離ラボ、データ保持要件の充足。§3 の隔離設計・ランブック・mock 検証を「統制の証明」として提出。
4. **データ保持の扱いを先に決める**: モニタリングのためのデータ保持が前提。ゼロ保持が必要なら、Fable 5.1 / Mythos 5.1 のゼロ保持アクセス、または EFS（今秋後半予定）を確認する。
5. **不変の一線**: Red Team でも、物理的被害・大規模な妨害につながる行為（ランサム展開、物理システムの破壊、高リスクな安全系へのペンテスト等）はブロック対象。
   本プロジェクトの方針（攻撃レシピ・安全フィルタ除去を作らない）と整合。

---

## 参考

- [Anthropic — Cyber Verification Program](https://www.anthropic.com/news/cyber-verification-program)（公開日 2026-10-06）
  - Project Glasswing と従来の CVP を統合した拡張枠組み。「サイバーセキュリティは本質的に二面性がある」ため、検証された防御者に限定して提供。
  - Glasswing の成果: パートナーが**少なくとも 12.9 万件**の検証済みソフトウェア脆弱性を報告（2026/4–7）。Anthropic 自身の OSS スキャンでさらに 5,500 件（2026/4–10）。
    うち **3.3 万件超が critical/high**。公式は**過小計上**で、実際の影響は「少なくとも 5 倍」と推定。
  - CyScenarioBench（Opus 5.5、10 シナリオ × 5 回 = 各ティア 50 試行）: CVP なしは最初のプロンプトで全てブロック。
    Defense は 50 件中 46 件がどこかでブロック（4 件は成功）。Red Team はブロックなしで 50 件中 34 件を完遂（防護なしと「実質同等」）。
    → **Defense は悪性の多段攻撃をほぼ止める**設計。
- 申請: https://portal.anthropic.com/programs/cvp ／ ティア詳細の Help Center: https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet
