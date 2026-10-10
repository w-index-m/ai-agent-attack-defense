# patch_suggest: 診断結果から修正案(diff)を作る（自動適用はしない）

English summary: see the end of this file.

チェック（Semgrep/Trivy/gitleaks/netcheck）→ 見つかった箇所の一覧（`vuln_triage.html`）の次の段階として、
**「直し方の提案」を実際の diff にする**ツール。`scripts/patch_suggest.py`。

> ⚠️ 方針：**自動でコードを書き換えるのではなく、diff を作るだけ**。適用（`--apply`）は、**1件ずつ人が diff を読んで確認してから**。
> 小さいローカルモデル（qwen2.5:1.5b 等）はコード生成の精度が低いため、必ず人の確認を挟む設計にしている。

## 対象にする指摘（安全側に絞っている）

| 診断結果 | 扱い |
|---|---|
| **Semgrep / SARIF**（コードの指摘） | 自前LLM（OpenAI互換エンドポイント）に、該当箇所だけを直す最小限の diff を作らせる |
| **Trivy の脆弱性**（`FixedVersion` あり） | LLM を使わず、マニフェストのバージョン表記を書き換えるだけの**決め打ちパッチ**（文脈2行つき）。LLMに依存ファイルの中身を自由に書かせるより安全 |
| **gitleaks**（秘密情報） | **対象外。** 秘密情報をLLMに渡すこと自体がリスクなので、「手動でローテーションしてください」と案内するだけ |
| **netcheck / zgrab2**（露出の指摘） | 対象外（コードではなく設定・運用の話のため） |

## 安全のための制限

- **適用は常に人の確認（`y`/`N`）が必須。** 自動で全件適用するフラグは無い（意図的に実装していない）。
- 対象ファイルは、指定したリポジトリ直下の**外に出られない**（`../` 等のパス脱走を拒否。テストで確認済み）。
- 実在しないファイル、大きすぎるファイル（200KB超）は対象外。
- LLM への送信は、**指定したエンドポイントだけ**。秘密情報の値は渡さない。
- 実行・適用の記録は `scripts/patch_suggest.log` に残る（Git管理外）。
- 生成した diff は `patches/`（既定。Git管理外）に置かれる。

## 使い方

```bash
# 1) 診断結果(semgrep.json 等)から、修正案(diff)を作るだけ。何も変更しない。
python3 scripts/patch_suggest.py results/ --repo . \
  --llm-url http://localhost:11434/v1 --llm-model qwen2.5:1.5b

# 2) 作った diff を読む(patches/ の中身)。問題なければ、1件ずつ確認しながら適用する。
python3 scripts/patch_suggest.py results/ --repo . --apply
```

## 確認したこと（検証）

- Semgrep の指摘（SQL文字列の連結）→ LLMが提案したプレースホルダ化の diff を、確認後に適用できることを確認。
- Trivy の脆弱性（`FixedVersion` あり）→ `requirements.txt` のバージョン表記だけを書き換える diff が、`git apply` で問題なく当たることを確認（文脈0行では `git apply` が失敗することがあったため、前後2行の文脈を含める形に修正済み）。
- gitleaks の検出値（秘密情報）は、**LLMに一度も送信されないこと**を、モックサーバーへの実際のリクエストを見て確認。
- パス脱走（`../../etc/passwd` 等）・存在しないファイルを指す指摘は、**diff を作らず対象外**にすることを確認。
- 適用時に `N` と答えたファイルは変更されないこと、`y` と答えたファイルだけが変更されることを確認。

## 正直な限界

- **qwen2.5:1.5b のような小さいモデルは、コード生成を間違えることがある。** 診断の意味を取り違えたり、動かないdiffを出すことがある。**必ず人が読んで、テストを実行してから使うこと。**
- LLMが作る diff は「それらしい見た目」でも、**実際には的外れな修正**のことがある。特にロジックが複雑な箇所は、小さいモデルほど外しやすい。
- Trivy の決め打ちパッチも、**バージョンを上げるだけで動作確認はしない**（互換性の破壊は検知できない）。
- 大規模な指摘件数には向かない（既定で1回に送るのは10件まで）。

> 検知・防御・修正支援の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。

---

## English summary

`scripts/patch_suggest.py` turns findings from Semgrep / SARIF (code-level) and Trivy (dependency CVEs with a known
fixed version) into **proposed diffs** — it never edits files automatically. For code findings it asks your own
local LLM (OpenAI-compatible endpoint, e.g. Ollama) for a minimal unified diff; for Trivy it does a deterministic
version-bump in the manifest (no LLM involved, safer than letting a model rewrite a dependency file). gitleaks
findings (secrets) are **out of scope** — their values are never sent to the LLM, and the tool only tells you to
rotate them manually. Applying a patch (`--apply`) always requires a human `y`/`N` confirmation per file; there is
no "apply all" flag by design. Target paths are confined to the given repository root (path traversal is rejected),
and oversized or missing files are skipped. Verified: real end-to-end runs (generate → review → apply) against a
disposable git repo and a mock OpenAI-compatible server, confirming secrets are never transmitted, patches outside
the repo root are rejected, and only confirmed patches change files. Honest limit: small local models (e.g.
qwen2.5:1.5b) can propose incorrect fixes — always read the diff and run tests before trusting it.
