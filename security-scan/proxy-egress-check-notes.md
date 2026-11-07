# proxy_egress_check: フォワードプロキシログからR1/R4を確認するツール

## 経緯

`security-scan/detections/README.md`のR1-R7「検知ログ源・想定ツール」一覧を書いた際に、
「R1/R4が検知ログ源としているフォワードプロキシログを、実際に読み込んで判定するツールは
このリポジトリに無いのでは?」という指摘があり、確かに無かった(2026-11-07)。

`security-scan/detections/sigma/r1_llm_api_egress.yml`・`r4_messaging_api_c2.yml`は、あくまで
「どう見れば検知になるか」という**ルール定義**で、Sigma/Datadog/Elasticのクエリ文法で書き
起こしてはいるが、実際に投入する先はSIEM側(Splunk・Datadog・Elastic等)が前提。SIEMを持たない
個人・小規模環境では、そのままでは使えない。

`scripts/proxy_egress_check.py`は、このギャップを埋める、**ログファイルを直接読む版**。

## やること(確認専用、読み取りのみ)

- フォワードプロキシのアクセスログ(Squid native形式、またはJSON Lines形式)を読む。
- 宛先ホストが、R1(LLM API: `api.openai.com`・`api.anthropic.com`・`api.openrouter.ai`等)・
  R4(メッセージングAPI: `api.telegram.org`・`discord.com`・`slack.com`等)のドメイン一覧に
  一致するものを拾う。ドメイン一覧はSigmaルールと完全に同じ(コピー元はそちら)。
- `--server-cidr`で対象の送信元IP範囲を絞り込み、`--exclude-cidr`で既知の開発者端末等を除外
  できる(指定が無ければ全件対象。これはSigmaルールの「src_network_zoneは環境依存、既定では
  絞らない」という設計と同じ)。
- ネットワーク通信は一切しない。ログの改変もしない。

## 使い方

```bash
python3 scripts/proxy_egress_check.py --log-path /var/log/squid/access.log
python3 scripts/proxy_egress_check.py --log-path proxy.jsonl --format jsonl --server-cidr 10.0.0.0/8
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗・CIDR指定不正)。

## 確認したこと(2026-11-07、このサンドボックス内)

- Squid native形式の合成ログ(R1該当2件・R4該当1件・無関係2件)で、該当3ペア(計4行)を
  正しく検出し、無関係な宛先(`www.example.com`・`notreal.example.net`)では誤検知0件。
- JSON Lines形式の合成ログ(`dest_host`キー・`url`キーの両方)で、R1該当1件・R4該当1件を
  正しく検出。
- `--server-cidr 10.0.0.5/32`で絞り込むと、対象外の送信元(`10.0.0.9`由来のR1/R4)が除外され、
  対象内(`10.0.0.5`)のR1のみ残ることを確認。
- `--exclude-cidr 10.0.0.9/32`で除外すると、同様に`10.0.0.9`由来の分だけ除外されることを確認。
- ヒットが無いログでは、終了コード0・「見つかりませんでした」の表示を確認。

## 確認していないこと

- 実際に稼働しているSquid(またはその他のフォワードプロキシ製品)が出力する**本物の**アクセス
  ログでの動作(今回はすべて合成ログでの検証)。特にSquidのログ形式は設定(`logformat`)で
  カスタマイズ可能なため、native形式以外のカスタムフォーマットには対応していない。
- Squid以外の主要なフォワードプロキシ製品(Blue Coat/Symantec ProxySG、Zscaler、Forcepoint等)
  の独自ログ形式。JSON Lines形式で出力できる製品であれば、キー名が`_SRC_KEYS`/`_HOST_KEYS`/
  `_URL_KEYS`(スクリプト内の定数)のいずれかに一致すれば動く設計だが、未確認。
- 大規模ログ(GB単位)での性能(全行をメモリに読み込む実装のため、非常に大きいログでは
  ストリーミング処理への変更が必要になる可能性がある)。
