# Security Policy / セキュリティ方針

## English

This is a **defensive, educational** repository: detection rules, exposure checks,
and analysis notes based on the Gambit report on AI-agent attacks. It contains
**no exploit code, attack recipes, or safety-bypass techniques**, and the included
tools are confirmation/detection only.

**Use only on systems you own or are explicitly authorized to test.**

### Reporting a vulnerability
If you find a security issue *in this repository's own code* (e.g. `netcheck`,
`scripts/summarize.py`, `vuln_triage.html`, the CI workflow):

- Prefer **GitHub's private vulnerability reporting** (repository → *Security* →
  *Report a vulnerability*).
- Or open a regular issue for non-sensitive problems.
- **Do not** include secrets, tokens, or real target data in a report.

We aim to acknowledge reports within a few days. There is no bounty; this is a
volunteer, open-source project.

### Out of scope
Vulnerabilities in third-party tools analyzed here (Strix / Cairn / Hermes) or in
the scanners this repo integrates (Semgrep / Trivy / gitleaks / ZAP) should be
reported to those projects, not here.

---

## 日本語

本リポジトリは **防御・教育目的**（AIエージェント攻撃の検知ルール・露出確認・解析ノート）です。
**攻撃コード・攻撃手順・安全機構の回避手法は含みません**。付属ツールは確認／検知専用です。

**自分が所有している、または明示的に許可を得た対象にのみ使用してください。**

### 脆弱性の報告
本リポジトリ自身のコード（`netcheck` / `scripts/summarize.py` / `vuln_triage.html` / CI ワークフロー等）に
問題を見つけた場合：

- **GitHub の非公開脆弱性報告**（リポジトリ → *Security* → *Report a vulnerability*）を推奨。
- 機微でない内容なら通常の Issue でも可。
- 報告に**シークレット・トークン・実対象のデータを含めない**でください。

数日以内の初動を目標にします。報奨金はありません（ボランティアの OSS プロジェクトです）。

### 対象外
解析対象の第三者ツール（Strix / Cairn / Hermes）や、連携するスキャナ（Semgrep / Trivy / gitleaks / ZAP）の
脆弱性は、各プロジェクトへ報告してください。
