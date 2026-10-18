# GHSA（GitHub Security Advisory）の構造化データ抽出（`scripts/ghsa_lookup.py`）

English summary: see the bottom of this file.

## 作った理由

このリポジトリでは、Metabase・Semantic Kernel・ModelScope の CVE を調べる過程で、**アドバイザリの
ページを LLM に読ませて要約させた**ことで、**2 つの CVE の内容を取り違える誤り**が実際に起きた
（`llm-target-attacks.ja.md` の修正履歴を参照）。GitHub は、公開アドバイザリを**構造化データ（JSON）**
でも提供しているので、要約させず、**フィールドをそのまま転記するだけ**にすれば、同じ種類の誤りを防げる。

## できること

- GHSA ID（`--ghsa GHSA-xxxx-xxxx-xxxx`）または CVE 番号（`--cve CVE-YYYY-NNNNN`）を指定すると、
  GitHub の公開 Advisories API から、概要・重大度・CVSS・CWE・影響版・修正版・参照リンクを取得し、
  Markdown に整形する。
- **要約・言い換えは一切しない。** API が返した値をそのまま書き出す。
- 取り下げられたアドバイザリ（`withdrawn_at` あり）は、警告つきで明示する。
- 見つからない・接続できない場合は、**その旨を明示する**（黙って空の結果にしない）。

## 使い方

```
python3 scripts/ghsa_lookup.py --ghsa GHSA-xjw9-4gw8-4rqx --out report.md
python3 scripts/ghsa_lookup.py --cve CVE-2026-26030 --cve CVE-2026-25592 --out report.md
```

## 検証の状態（正直に）

- **JSON のパースと Markdown への整形**：ローカルのモック HTTP サーバー（実際に確認した
  GHSA-xjw9-4gw8-4rqx のデータを再現したもの）で検証済み。404（見つからない場合）、CVE 番号での
  検索、`first_patched_version`（オブジェクト形式）からの修正版の抽出を確認した。
- **実際の `api.github.com` への接続**：**この開発環境からは確認できていない。** 理由は、ネットワーク
  自体の制限ではなく、**このセッションの GitHub 連携が、接続済みリポジトリ以外の API パスへのアクセスを
  塞いでいる**ため（`api.github.com/advisories/...` への `curl` が、Claude Code 側のメッセージを返した）。
  一般的なインターネット接続がある環境（自分の PC、CI）であれば、この制約は無いはずだが、未確認。
- GitHub の公開 Advisories API は、**認証なしでも読めるが、レート制限が低い**（認証ありより少ない回数）。
  連続して多数のアドバイザリを取得する場合は、`--delay` の間隔を空けることを推奨する（既定 1 秒）。

## 限界

- GitHub の API のレスポンス形式は、`cvss`（単一）と `cvss_severities`（複数版）、
  `patched_versions`（文字列）と `first_patched_version`（オブジェクト）など、**時期により形が違う**。
  両方に対応しているが、将来の API 変更には追従できない可能性がある。
- GHSA に登録されていないアドバイザリ（独自のベンダー勧告のみのもの、VulnCheck など別の採番機関のみの
  もの）は取得できない。今回の Context7（CVE-2026-75130）はこれに該当し、この道具では取得できない。

---

## English summary

`scripts/ghsa_lookup.py` fetches a GitHub Security Advisory's **structured JSON** (by GHSA ID or CVE
number) from the public Advisories API and writes it to Markdown **verbatim, with no summarization**.
This exists because summarizing an advisory page with an LLM earlier led to mixing up two distinct
CVEs' contents (see the revision history of `llm-target-attacks.en.md`). Parsing and formatting were
verified against a local mock server reproducing GHSA-xjw9-4gw8-4rqx's real data; the real
`api.github.com` endpoint could not be reached from this development environment (this session's
GitHub integration blocks API paths outside the attached repository, not a general network
restriction) and has **not** been verified. Advisories that exist only outside GHSA (e.g., a
VulnCheck-only advisory such as Context7's CVE-2026-75130) cannot be fetched by this tool.
