# shared — 共有定義（single source of truth）

このリポジトリには、ブラウザ完結の `vuln_triage.html`、スタンドアロンの `netcheck`、
`security-scan/detections/` の各種検知ルール、ダッシュボード、ノート類…と、**独立して動く
ツールが複数**あります。それぞれが自己完結（オフライン・単一ファイル・標準ライブラリのみ）
であることは意図した設計なので、**実行時に共通ライブラリを読み込ませて一本化はしません**。

代わりに、各ツールに点在してコピーされがちな「共通の定義」を 1 か所に集め、
**追従できているかを CI で検査する（drift guard）**ことで、
「片方だけ更新して他方を忘れる最新化漏れ」を防ぎます。

## 構成

- [`taxonomy.json`](taxonomy.json) — **唯一の定義**。以下を一元管理します。
  - `detection_tags` … 検知/防御タグ **R1–R7 / ③ / ③CSP**（id と名前）
  - `governance_events` … ガバナンス監査イベント **G1–G6**
  - `attack_chain` … Gambit 報告の攻撃連鎖 7 段
  - `triage_scanners` … `vuln_triage.html` が取り込めるスキャナ形式
  - `detections_coverage` … 検知ルールの**網羅表**（どのタグをどのバックエンドで実装したか）
- [`../tools/check_consistency.py`](../tools/check_consistency.py) — **ズレ検知**。標準ライブラリのみ、
  ネットワーク・サブプロセスなし。`python3 -I tools/check_consistency.py` で実行。
  CI（`.github/workflows/security-scan.yml` の `consistency` ジョブ）で毎回走り、ズレがあれば失敗します。

## 何を検査するか

1. `netcheck.py` / `vuln_triage.html` が使う R タグが `taxonomy` に定義済みか
2. `vuln_triage.html` の対応スキャナ（`parseOne` と絞り込み UI）が `triage_scanners` と一致するか
3. `vuln_triage.html` の攻撃連鎖（`CHAIN`）が `attack_chain` と一致するか
4. `security-scan/detections/`（sigma / datadog / elastic / falco）のルール有無が `detections_coverage` の網羅表と一致するか
5. R1–R7 が `detections/README.md` と `defense-detection-notes.md` に記載されているか

## 追加のチェックリスト（最新化漏れを防ぐ）

**新しい検知/防御タグを足すとき**（例: R8）
1. `taxonomy.json` の `detection_tags` に `R8` を追加
2. 使う側（`netcheck.py` の `PORT_RULE` / `add(...)`、`vuln_triage.html` の `RULES`）に反映
3. `detections_coverage.matrix` に `R8` の行を追加し、実装したバックエンドを `true` に
4. 実装した各バックエンドにルールファイル（`r8_*.yml` 等）を追加、`detections/README.md` の表も更新
5. `defense-detection-notes.md` に R8 の節を追加
6. `python3 -I tools/check_consistency.py` が ✅ になることを確認

**新しいスキャナ形式を足すとき**（例: osv）
1. `taxonomy.json` の `triage_scanners` に `osv` を追加
2. `vuln_triage.html` の `parseOne` に取り込み分岐と、`f-tool` の `<option>` を追加
3. チェッカーが ✅ になることを確認

**netcheck に危険ポートを足すとき**
1. `RISKY` に説明を追加し、`PORT_RULE` で既存タグ（R1–R7 / ③）に対応づけ
2. プローブ対象（`STANDARD_PORTS` / `EXTENDED_PORTS` / `HTTP_PORTS` 等）にも追加
3. 使ったタグはすべて `taxonomy.json` に定義済みであること（新タグなら上記手順）

> 方針: 検知・防御の設計に限定。攻撃の実行手順や安全機構の回避方法は含めません。
