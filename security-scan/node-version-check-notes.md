# Node.js バージョン確認（確認専用）

`scripts/node_version_check.py`: Node.js本体が、CVE-2026-111497(Brotliデコーダの境界外
書き込み、RCEに繋がりうる脆弱性。[`detections/`](detections/) の R25 参照)の対象になりうる
かを確認する。R24(`python-brotli-check-notes.md`、PyPIの`brotli`/`brotlicffi`)の
**Node.js本体版**にあたる。

> ⚠️ 方針：**確認だけ**。Node.jsの更新、コードの実行、ネットワークへの送信は一切しない。

## 背景: CVE-2026-111497とR25の関係

根本原因はBrotliデコーダの境界外書き込み(out-of-bounds write)。攻撃者が細工したBrotliデータ
を展開させることで、メモリリークまたは任意コード実行に繋がりうる。元々Node.js本体の脆弱性と
して公開され、2026-10-21にNode.js公式が22.23.4/24.22.1/26.12.1で修正(同時にリリースされた
他9件のCVEのうち4件がhigh評価)。これより古いメジャーライン(20系以下)には、Node.js公式からの
修正が存在しない(サポート終了のため)。

**2026-10-25追記(裏取り結果)**: Node.js公式の2026-10-21セキュリティリリースにCVE-2026-111497
が含まれていることを、複数の独立したセキュリティニュースサイトの報道で確認した(本リポジトリの
`python-brotli-check-notes.md`で先に実施した裏取りと同じ結果)。一方、「HTTP2Shell」という
呼称、およびBun/Envoy Proxy/Istoへの波及については、単一の情報源(専用の脆弱性告知ページ)でしか
確認できておらず、独立した裏取りはできていない。本スクリプトの検証対象は引き続き**Node.js本体
のみ**とし、Bun/Envoy Proxy/Isto等への言及は未確証の情報として扱う。

R25のクラッシュ検知部分(`detections/sigma/r25_nodejs_brotli_node2shell.yml`等)は、R24と同じく
**R13(wp2shell)やR15(PHP2Shell)と違い、ベンダー/研究者が公開したリクエスト単位・ログ単位の
IOCが無い**ため、本リポジトリ独自に構成した未確証の探索的ヒューリスティック(Node.jsプロセスの
クラッシュパターンを、brotli文脈の近くで探すだけ)である。本スクリプトはそれを補完する、ホスト側の
**バージョン確認**ツール。

## できること

- **既定**: `node --version`を実行し(ネットワークアクセスなし)、メジャーライン(22/24/26系)
  ごとの修正版と照合する。
- **`--node-path <path>`**: PATH上の`node`ではなく、指定したNode.js実行ファイルを確認する。
- **ログ確認(任意、`--log-path` または `--journalctl-unit`)**: アプリケーションログから、
  R25のSigmaルールと同じパターン(SIGSEGV/core dumped等のNode.jsプロセスクラッシュ行が
  brotli文脈の近くにあるか)を確認する。R25自体が未確証のヒューリスティックであるため、この
  確認結果も同様に「調査すべき手がかり」止まりである点に注意。
- SARIF 2.1.0 での出力にも対応(`--out`)。`vuln_triage.html` に読み込める。

## できないこと・正直な限界

- 22/24/26系以外のメジャーライン(20系以下等)は、Node.js公式が修正版を出していないため、
  バージョン比較ではなく「対応ラインに含まれない」という`medium`判定にとどまる。
- ログ確認は、R25自体がベンダー未公開のヒューリスティックであるため、ヒットしても
  CVE-2026-111497固有の確証にはならない(他の原因のプロセスクラッシュでも同じ形になりうる)。
- パッケージ自体のバグを検査するわけではない(動的なエクスプロイト再現は行わない)。
- Bun/Deno等、Node.js以外のJavaScriptランタイムは対象外(現時点でこれらへの波及は本リポジトリ
  では未確証のため)。

## 使い方

```bash
python3 scripts/node_version_check.py
python3 scripts/node_version_check.py --out node_check.sarif
python3 scripts/node_version_check.py --node-path /path/to/node
python3 scripts/node_version_check.py --log-path /var/log/myapp/node.log
```

## 検証

- このサンドボックス環境の実際のNode.js(`v22.22.0`、修正版22.23.4未満)に対して実行し、
  正しく`high`判定になることを確認した。
- **修正版での検証**: `v22.23.4`を返すダミーのNode.js実行ファイルを用意し、`--node-path`経由
  で確認したところ、正しく`info`判定(修正版以降)になることを確認した。
- **未対応ラインの検証**: `v18.20.4`を返すダミーのNode.js実行ファイルに対して、正しく
  `medium`判定(22/24/26系に含まれない)になることを確認した。
- ログ確認は、合成したNode.jsクラッシュログ(`Segmentation fault (core dumped)`の近くに
  `Content-Encoding: br`への言及があるもの、および brotli文脈を伴わない無関係なクラッシュ行の
  両方を含む)でテストし、brotli文脈を伴う1件のみを正しく検知し、無関係な1件は検知しないことを
  確認した。
- SARIF出力が有効なJSONとしてパースできることを確認した。

> 確認・検知の設計に限定。攻撃の実行手順やエクスプロイトコードは含めない。
