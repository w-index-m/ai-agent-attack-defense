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
- **実際の `api.github.com` への接続**：**2026-10-30、Windows の PC で確認済み。** `--ghsa GHSA-xjw9-4gw8-4rqx`
  は取得 1件・失敗 0件、`--cve CVE-2026-26030 --cve CVE-2026-25592` は取得 2件・失敗 0件。
  クラウド開発環境（ネットワーク許可リスト制）からは 403 で拒否され、接続失敗として明示された（空の結果にはならなかった）。
  取得内容が GitHub 上のページと一致するか（特に 2つの CVE が混ざっていないか）の照合は、まだ行っていない。
- GitHub の公開 Advisories API は、**認証なしでも読めるが、レート制限が低い**（認証ありより少ない回数）。
  連続して多数のアドバイザリを取得する場合は、`--delay` の間隔を空けることを推奨する（既定 1 秒）。

## 限界

- 実通信（2026-10-30）で、`--cve CVE-2026-26030 --cve CVE-2026-25592` が 2件とも取得でき、2つの CVE は別の節に分かれ、
  CWE・CVSS・修正版がリポジトリ内の既存の記述（`llm-target-attacks.ja.md`）と一致することを、出力の目視で確認した。
  CVSS の重複（各節に4行→1行ずつ）と「状態: (無し)」行の修正も、修正後の出力で確認した（`**CVSS**` 行が2、`**状態**` 行が0）。
- 実通信で、CVSS が `cvss` と `cvss_severities` の両方に同じ値で返ることを確認した。同じ値は1回だけ出す。
  グローバルな Advisories API のレスポンスには `state` が無いので、無い場合は「状態」の行を出さない。

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
`api.github.com` endpoint was verified on a Windows PC on 2026-10-30 (1 GHSA and 2 CVE lookups
all succeeded). The fetched content has not yet been cross-checked against the advisory pages.
From the cloud dev environment (allow-listed network) the calls got 403 and were reported as
connection failures rather than empty results. Advisories that exist only outside GHSA (e.g., a
VulnCheck-only advisory such as Context7's CVE-2026-75130) cannot be fetched by this tool.
