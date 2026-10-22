# Java cacerts の eMudhra関連ルートCA確認（確認専用）

`scripts/java_cacerts_emudhra_check.py`: ローカルの Java(OpenJDK/Oracle JDK)の cacerts(信頼ストア)に、
eMudhra の侵害されたCA(2026-10、[`lineage.md`](lineage.md) / `detections/` の R14 参照)に連なる
ルートCAが含まれているかを確認し、`java -version` をIPAの注意喚起(2026-10-21)が列挙した
「脆弱な版」一覧と突き合わせる。

> ⚠️ 方針：**確認専用**。cacerts の変更、ネットワークへの送信は一切しない。実行するのは、
> そのホストの `keytool`/`java` だけ。**自分が管理する機器でだけ実行する。**

## 背景: CVE-2026-91403とR14の関係

R14(`detections/sigma/r14_emudhra_compromised_ca_trust.yml` 等)は、「ブラウザ以外のTLSクライアント
(curl、各言語ランタイムの同梱証明書束、…)は更新サイクルが別」という前提で作った検知ルールだった。
CVE-2026-91403(CVSS 9.1、Oracle Security Alert、IPAも同日注意喚起)は、**その具体例が実際に
確認されたもの**: OpenJDK/Oracle Javaのcacertsが、侵害された中間CAが連鎖するルートCA
(`emSign ECC Root CA - G3` 等、`AAA Certificate Services`)を信頼済みだったため、JSSE経由で
不正な証明書チェーンを検証してしまう恐れがあった。Oracleの修正は、該当ルート自体ではなく、
**侵害された中間CAだけを個別に不信任にする**方式。

## できること

- cacerts に、Owner(発行者)が `emSign` または `AAA Certificate Services` を含むエントリが
  あるかを確認(`keytool -list -v -cacerts` の出力を読むだけ)。
- `java -version` の出力を、IPAが「脆弱な版」として列挙したバージョン文字列
  (`27`, `26.0.2`, `25.0.4.1`, `21.0.12.1`, `17.0.20.1`, `11.0.32.1`, `8u503`)と突き合わせる。
- SARIF 2.1.0 での出力にも対応(`--out`)。`vuln_triage.html` に読み込める。

## できないこと・正直な限界

- **ルートCAの存在だけでは「脆弱」の確証にはならない。** Oracleの修正方式(ルートではなく
  侵害された中間CAだけを個別ブロック)のため、この確認だけではパッチ適用状況は判定できない。
  最終判断は、Oracle公式のSecurity Alert(CVE-2026-91403)と、インストール済みJavaの正確な
  バージョンで行うこと。
- IPAの「脆弱な版」一覧は固定のバージョン文字列のみ。一覧外(より古い版、より新しい未確認の版)が
  安全という意味ではない。
- cacerts のパスワードは既定で `changeit`(JDK標準)。変更している場合は `--storepass` で指定。

## 使い方

```bash
python3 scripts/java_cacerts_emudhra_check.py
python3 scripts/java_cacerts_emudhra_check.py --out java_cacerts_emudhra.sarif
python3 scripts/java_cacerts_emudhra_check.py --storepass <custom>
```

## 検証

- このサンドボックス環境の実際のJDK(OpenJDK 21.0.12.1)に対して実行し、動作を確認した:
  - cacerts のエントリ123件を正しく解析(`Owner:` 行の抽出は、既知のDigiCert系エントリ7件を
    正しくマッチすることで検証済み)。
  - `emSign`/`AAA Certificate Services` 該当エントリ無し → 正しく「見つかりませんでした」と報告。
  - **興味深い実例**: このサンドボックスのJava(`21.0.12.1`)は、偶然にもIPAの「脆弱な版」一覧に
    **一致**し、ツールは正しく警告を出した(ただしこのサンドボックス自体は実運用機ではないため、
    対応の要否はない)。
  - `--storepass` 誤り時のエラーハンドリングを確認。初期実装では `keytool` のエラーメッセージが
    環境によって stdout 側に出ることを見落としており(`stderr` だけを見ていたため、意味のない
    `JAVA_TOOL_OPTIONS` の雑音行しか拾えていなかった)、`stderr`+`stdout` を結合する修正を行い、
    再検証した。
  - `keytool`/`java` が見つからない場合のエラーメッセージも確認(クラッシュせず、明確な終了)。
- **実機(実際にeMudhra系ルートCAを含むcacerts)では未検証。** emSign/AAA Certificate Services を
  実際に含む環境がこのサンドボックスには無いため、該当エントリが見つかった場合の出力は
  コード上の確認のみ(`find_suspect_roots()` のロジック自体は、既知のDigiCertエントリへの
  マッチで間接的に検証済み)。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
