# proxy_egress_check: フォワードプロキシログからR1/R4/R9/R10を確認するツール

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
- R9(エージェント系User-Agentから許可リスト外ドメインへのegress)・R10(クラウドメタデータ
  サービスの資格情報エンドポイントへのアクセス)も同じツールで検知する(2026-11-08追加)。
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

## 2026-11-07追記: Groq・Google Gemini/Gemmaのドメインを追加

会話での指摘(「Gemma や Groq 経由でもAIエージェント攻撃になるか」)をきっかけに、R1のドメイン
一覧に`api.groq.com`(Groq、モデルではなく推論ホスト。Llama/Gemma/Mixtral等を高速提供)と
`generativelanguage.googleapis.com`(Google Gemini/Gemmaの公開API)を追加した。

「どのLLMベンダー・推論ホストを使うか」は検知の本質とは無関係(判断の主体がLLMであれば対象)。
ただし、**完全にローカルで動くモデル(Ollama等)を使われた場合、そもそも外向き通信が発生しない
ため、このルール(R1)では原理的に検知できない**(`strix-local-poc/`で実際に確認済みの限界。
その場合に残る手がかりはR7「多数のツールの短時間連続実行」)。

sigma(`r1_llm_api_egress_from_servers.yml`)・datadog・elastic(単体ファイルとndjson両方)・
falco(`cairn-ai-agent.yaml`)・`proxy_egress_check.py`の計6箇所を同時に更新し、ズレが無いことを
確認(JSON/NDJSONはパース確認、`tools/check_consistency.py`もOK)。`proxy_egress_check.py`は、
合成ログ(`api.groq.com`・`generativelanguage.googleapis.com`・無関係1件)で、新しい2ドメインを
正しく検出し、無関係な宛先での誤検知が無いことを確認した。

## 2026-11-08追記: R9(IDPI誘導egress)・R10(クラウドメタデータアクセス)を追加

「Gate 0のR1-R12、実機検証できそうなものありますか?」という質問をきっかけに、同じ
`proxy_egress_check.py`にR9・R10の検知ロジックを追加した。

- **R9**(`r9_idpi_steered_egress.yml`): `python-requests`・`node-fetch`・`LangChain`・`AutoGen`・
  `CrewAI`・`openclaw`等のエージェント系User-Agentから、許可リスト外ドメインへの通信を見る。
  `--r9-allowlist-suffix`で許可ドメインサフィックスを指定可能(指定が無ければ全件対象)。
  **User-AgentはSquid native形式のログには含まれないため、JSON Linesの`user_agent`キーが
  無いと判定できない**(Squid形式では常にスキップされる、既知の限界)。
- **R10**(`r10_metadata_service_credential_access.yml`): `169.254.169.254`・
  `metadata.google.internal`・`metadata`への、資格情報エンドポイントパス
  (`/computeMetadata/v1/instance/service-accounts/`等)へのアクセスを見る。CONNECT(HTTPS
  トンネル)ではパスが見えないため、平文HTTP(GET等)のみ判定可能。

### 確認したこと(2026-11-08、このサンドボックス内)

- JSON Lines合成ログで、R9該当2件(うち1件は許可リスト指定で正しく除外)・R10該当1件を正しく
  検出。無関係な宛先(`www.example.com`)・資格情報パス以外へのメタデータアクセス
  (`/some/other/path`)では誤検知0件。
- Squid native形式の合成ログ(平文HTTPのGET)で、R10を正しく検出。
- R1/R4の既存の検出が、この拡張後も変わらず正しく動作することを再確認(回帰なし)。

## 2026-11-08追記その2: R31(暗号資産取引所APIへの通信)を追加

「gate0止まりのしょり」の指示で、`r31_server_crypto_exchange_api_egress.yml`を追加した。
Binance・Coinbase・Kraken・Upbit・Bithumb・OKX・Bybitのドメインへの通信を見る、既存のR1/R4/
R9/R10と同じ「ドメインリスト+contains一致」の仕組みで、追加は容易だった。

合成ログ(`api.binance.com`・`api.bybit.com`の2件・無関係な宛先1件)で正しく検出し、誤検知0件を
確認。R31自体は「事件との直接的な関係は未確認」という探索的ヒューリスティックであり、
実装できたことと実際の攻撃を正しく言い当てられることは別の軸の話である点は変わらない。

### 2026-11-08追記3: R31の一次情報源での再確認(Gate 3試行、結論は変化なし)

WebSearchでHunt.io(2026-11-04)の報告を再確認した結果、暗号資産取引所の管理画面・取引・
シェルアクセス・設定収集を狙うツール群の存在自体は確認できたが、**Hunt.io自身がこれらの
ツールと韓国の銀行侵害との関係を確認していない**という立場は変わっていなかった。つまり
「事件との直接的な関係は未確認」という本ルールの記述は、追加調査後も正確なままである
(裏取りによって限界の記述が強化されただけで、Gate 3への前進は無し)。

なお、CrowdStrikeが(二次情報源経由で)この侵害を中国系アクターに帰属させたとの報道があり、
これはHunt.io自身の推論とは独立した帰属経路。韓国警察による確定はまだ無い。これにより
`r31_server_crypto_exchange_api_egress.yml`の`description`を更新した。

## 確認していないこと

- 実際に稼働しているSquid(またはその他のフォワードプロキシ製品)が出力する**本物の**アクセス
  ログでの動作(今回はすべて合成ログでの検証)。特にSquidのログ形式は設定(`logformat`)で
  カスタマイズ可能なため、native形式以外のカスタムフォーマットには対応していない。
- Squid以外の主要なフォワードプロキシ製品(Blue Coat/Symantec ProxySG、Zscaler、Forcepoint等)
  の独自ログ形式。JSON Lines形式で出力できる製品であれば、キー名が`_SRC_KEYS`/`_HOST_KEYS`/
  `_URL_KEYS`(スクリプト内の定数)のいずれかに一致すれば動く設計だが、未確認。
- 大規模ログ(GB単位)での性能(全行をメモリに読み込む実装のため、非常に大きいログでは
  ストリーミング処理への変更が必要になる可能性がある)。

## 2026-11-08追記: R1・R4・R9・R10をGate 3に区分(`verification-gates.md`棚卸しとの整合)

R1・R4は、Gambit Securityが自社で発見・回収した攻撃者ステージングサーバーに基づく一次報告
(2026-09-22)を出典としており、これはGambit自身の一次情報源にあたる。R9・R10は、従来
Unit 42のトップページという曖昧な参照だったが、WebSearchで該当記事の具体的なURL
(`ai-agent-prompt-injection/`・`double-agents-vertex-ai/`)を特定し、`references`を
Unit 42自身の記事に差し替えた。直接fetchはいずれもブロックされているため、本文は複数の
独立した二次情報源の一致した報告で確認した。これにより4件ともGate 3に区分した。検知
ロジック自体(ドメインリスト+文字列一致)は確認済みシグネチャではなく、本リポジトリ独自の
構成のままである点は変わらない。


## 2026-11-09追記: CI回帰に組み込んだ

これまで「このセッション内で一度、合成ログで動作確認した」のみで、継続的な再検証の手段が
無かった。`security-scan/detection-fixtures/`に陽性/陰性の合成ログを同梱し、
`scripts/run_detection_regression.py`が`.github/workflows/security-scan.yml`の`scan`
ジョブから毎回(PR・push・毎日の定期実行)このスクリプトを実行し、陽性入力は必ず検知・
陰性入力は必ず誤検知0件であることを確認するようになった。壊れた場合は
`results/detection_regression.json`に記録され、`scripts/summarize.py`経由でCIの要約にも
出る。詳細は`scripts/run_detection_regression.py`自身のdocstring参照。
