# Contributing / コントリビュート方法

Thanks for your interest! / ご関心ありがとうございます。

This project is **defensive and educational**. Contributions are welcome as long as
they stay within that scope. / 本プロジェクトは**防御・教育目的**です。その範囲内であれば歓迎します。

## Scope policy / スコープ方針

- ✅ Detection rules, exposure checks, defensive notes, mappings to open standards,
  documentation, bug fixes, tests.
- ❌ Exploit code, attack recipes, weaponization, or safety-bypass / safety-filter-removal
  techniques. PRs containing these will be declined.
- Everything here is **detection / defense design only**.
- Use the tools **only on systems you own or are authorized to test.**

（日本語）検知ルール・露出確認・防御ノート・公開標準へのマッピング・ドキュメント・バグ修正・
テストは歓迎。攻撃コード・攻撃手順・兵器化・安全機構の回避/除去手法は**不可**（却下します）。
本リポは**検知/防御の設計に限定**。ツールは**所有／認可した対象のみ**に使用してください。

## Before you open a PR / PR を出す前に

1. **Keep the single source of truth in sync.** Detection tags (R1–R7 / ③), the attack
   chain, supported scanners, and the detection-rule coverage matrix are defined once in
   [`shared/taxonomy.json`](shared/taxonomy.json). When you add a tag, scanner, port, or
   rule, follow the checklist in [`shared/README.md`](shared/README.md).
2. **Run the consistency check** — it must pass (CI runs it too):
   ```
   python3 -I tools/check_consistency.py
   ```
3. **New detection rules carry standard mappings.** Include the relevant
   **MITRE ATT&CK** technique ID (and, where applicable, **MITRE ATLAS** / **OWASP Top 10
   for LLM Applications**) in the rule's metadata/heading, so others can line it up with
   what they already use. See `security-scan/defense-detection-notes.md` §3.
4. **Keep the tools self-contained.** `netcheck` is standard-library-only Python;
   `vuln_triage.html` is a single offline file. Don't add runtime network calls or heavy
   dependencies to them.
5. **Never commit secrets.** `.pre-commit-config.yaml` / `.gitleaks.toml` are set up —
   run them locally. CI (Semgrep / Trivy / gitleaks) must be green.
6. Write a clear PR description: what changed and why.

（日本語要約）①共通定義は `shared/taxonomy.json` に一本化、追加手順は `shared/README.md`。
②`python3 -I tools/check_consistency.py` を通す。③新ルールには ATT&CK（必要に応じ ATLAS /
OWASP-LLM）の ID を併記。④ツールは自己完結を維持（netcheck=標準ライブラリのみ、vuln_triage=単一HTML）。
⑤シークレットは絶対にコミットしない（pre-commit / gitleaks を実行、CI を緑に）。

## Adding a new detection pattern / 新しい検知パターンを足すとき

See the checklist in [`shared/README.md`](shared/README.md). In short: define the tag in
`taxonomy.json`, add the rule file(s) under `security-scan/detections/<backend>/`, update
the coverage matrix and `detections/README.md`, add a section in
`defense-detection-notes.md` (with standard mappings), then make the consistency check pass.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md) — use GitHub's private vulnerability reporting for issues
in this repo's own code.
