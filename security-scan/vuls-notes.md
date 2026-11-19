# Vuls の取り込み(実機未確認)

English summary: see the end of this file.

[Vuls](https://github.com/future-architect/vuls)(Future Architect 社の OSS)は、サーバーの OS パッケージやミドルウェアを
エージェントレスで調べ、公開済みの脆弱性(CVE)との照合結果を JSON で出すスキャナです。
本リポジトリでは、その結果 JSON を `vuln_triage.html` に貼ると、Trivy などと同じ画面で優先度順に並べられるようにしました。

> ⚠️ **実機未確認です**
> - 取り込みロジックは、私(Claude)が記憶している Vuls の出力構造と、**架空のデータ**
>   (`security-scan/vuls-fixtures/sample_result.json`)に基づきます。**本物の Vuls の出力では、まだ一度も確認していません。**
> - フィールド名(`scannedCves` / `affectedPackages` / `cveContents` / `cvss3Score` など)が実際と違えば、
>   該当する項目が空になる、または取り込まれません。その場合は、出力 JSON(機密を除いたもの)を教えてください。
> - Vuls のバージョンによる出力の違いも、確認していません。
> - **FutureVuls(クラウド型の有料サービス)は対象外です。** API や出力形式を確認できていないためです。
>   対象は OSS 版 Vuls の結果 JSON だけです。
> - Vuls は対象サーバーへ SSH などで接続して調べます。**自分が所有・管理しているサーバーだけ**に使ってください(本リポジトリの方針)。
>   このリポジトリは Vuls を実行せず、**出力の読み取りだけ**を行います。

## 1. 使い方

1. 自分の管理するサーバーで Vuls を実行し、結果の JSON を用意する(Vuls 側の手順は、Vuls の公式ドキュメントに従ってください)。
   結果は、通常 `results/<日時>/<サーバー名>.json` に保存されると理解しています(未確認)。
2. `vuln_triage.html` の貼り付け欄に JSON を貼る、またはファイルで選ぶ。ツールは**自動で判別**され、絞り込みに「Vuls」が加わります。
3. 1 台ぶんのオブジェクト、または複数台を並べた配列のどちらでも読めます。

解析はブラウザ内だけで行い、外部には送りません。

## 2. 取り込みの規則

| 項目 | 扱い |
|---|---|
| 判別 | `scannedCves` が **オブジェクト**のものを Vuls の結果とみなす(空 `{}` も可=0件)。配列の場合は、全要素がそうであること |
| 1 指摘の単位 | 1 CVE につき 1 件(サーバーごと) |
| 深刻度 | ① `cveContents` の CVSS3 スコア(nvd → jvn → redhat → ubuntu → debian … の順で最初のもの)② CVSS3 の文字評価 ③ CVSS2 のスコア ④ ディストリの評価(important=高、moderate=中 など)⑤ 何も無ければ「中」(根拠欄に明記) |
| スコアの境界 | 9.0 以上=緊急、7.0 以上=高、4.0 以上=中、0 超=低、0=情報 |
| 修正版 | `affectedPackages[].fixedIn` を表示。`notFixedYet: true` は「まだありません」 |
| 公開された攻撃コード | `exploits` / `metasploits` が空でなければ、詳細欄に件数を注記(深刻度は変えない) |
| 差分表示 | `diffStatus` が `"-"`(解消済み)のものは取り込まず、件数を「未成功/対象外」に出す |
| 場所の表示 | `サーバー名 (パッケージ名)`。パッケージが無く CPE のみのときは CPE を表示 |
| 文字の扱い | 制御文字を空白にし、長い文は 300 字で切る(表示と、自前LLMへ渡すデータの安全のため) |

指摘は、Trivy の依存関係の脆弱性と同じ「使っている部品・製品の既知の脆弱性」の分類になります。
**脆弱性の有無の判定は Vuls の仕事**で、ここでは並べ替えと直し方の表示だけを行います。

## 3. 検証の範囲

- ✅ 架空データでのユニットテスト(`tools/test_ai_guards.py` の `TestVulsParse`、node で実行)。深刻度の優先順、境界値、
  修正版の表示、解消済みの除外、複数台、他形式の誤判別が起きないこと、制御文字の除去。
- ✅ テストの弱点探し(コードを少し壊して、テストが失敗するかを確認)で、見つかった抜けを補強済み。
- ❌ **本物の Vuls の出力での確認は未実施。**
- ❌ Vuls の複数バージョン、`vuls report` の他の形式(`-format-one-line-text` など)は対象外。JSON だけです。

## 4. 次にやること(あなたの手元で)

本物の出力が手に入ったら、機密(サーバー名・IP・内部のパッケージ名など)を伏せて、1 件ぶんだけでも見せてください。
フィールド名が違えば、`vuln_triage.html` の `vuls-parse` 区間と、`security-scan/vuls-fixtures/` を直します。

---

## English summary

Imports the JSON output of [Vuls](https://github.com/future-architect/vuls) (OSS, agentless vulnerability scanner) into
`vuln_triage.html`. **Not verified against real Vuls output**: the parser follows the structure the author recalls
(`scannedCves`, `affectedPackages`, `cveContents`, CVSS fields) and is unit-tested only with synthetic data
(`security-scan/vuls-fixtures/sample_result.json`). FutureVuls (the paid cloud service) is out of scope. This repository
only reads Vuls output; it never runs Vuls. Run Vuls only against servers you own or manage.
