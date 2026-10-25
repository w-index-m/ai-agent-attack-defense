# BIND 9 バージョン確認（確認専用）

`scripts/bind_version_check.py`: ISC BIND 9の2026-10-21セキュリティリリース(4件のCVE、
BIND 9.20.30 / 9.21.27 / 9.20.30-S1で修正。[`detections/`](detections/) の R22 参照)の対象に
なりうるかを確認する。

> ⚠️ 方針：**確認だけ**。named の設定変更、ゾーンデータの書き換えは一切しない。
> ネットワークへの送信は「CHAOS TXT問い合わせ」1回のみ(`--query`を指定した場合だけ)。

## 背景: 2026-10-21のBIND 9セキュリティリリースとR22の関係

R22(`detections/sigma/r22_bind_gsstsig_memcorrupt.yml` 等)は、namedのクラッシュログ
(assertion failure特有の`INSIST(`等)とGSS-TSIG/TKEY文脈の組み合わせ、および別口でCHAOS版数
バナーからの修正前バージョン検知という、2本立てのログ/ネットワーク観測に基づく検知ルード。
本スクリプトはそれを補完する、ホスト側の**バージョン確認**ツール: 「このホスト(またはこの
リゾルバ)のBINDはそもそも対象バージョン範囲にあるか」を直接調べる。

4件のCVEのうち最も深刻なのはCVE-2026-94300(CVSS 8.1): GSS-TSIGで署名されたUDPメッセージの
リプレイでnamedのメモリが破損し、ISC自身の表現では「自分が管理するゾーンへの細工クエリと
組み合わせると**潜在的に**リモートコード実行に繋がりうる」(確定ではなく条件付きの表現)。
報告者はOpenAIのDave Aitel。回避策なし。他3件(CVE-2026-96888/CVE-2026-19630/CVE-2026-97313)
はDoS系(assertion failureでの異常終了、リソース枯渇)。

## できること

- **ローカルモード(既定)**: このホストの `named -v` の出力を読み取り、既知の影響範囲
  (9.11.0〜9.18.50、9.20.0〜9.20.29、9.21.0〜9.21.26)と近似照合する。
- **ネットワークモード(`--query HOST`、要`--i-own-these`)**: 指定したリゾルバへCHAOSクラスの
  TXTレコード(`version.bind`)を1回だけ問い合わせ、応答のバージョン文字列を照合する。これは
  BIND運用で広く使われる標準的な確認手法そのもの(`dig -c CHAOS -t TXT version.bind` と等価)。
  対象は`netcheck`と同じ許可範囲判定(既定: 社内のプライベートIP)に限定し、`scripts/
  zgrab2_guard.py`と同じく`netcheck/netcheck.py`の判定ロジックを再利用する。
- SARIF 2.1.0 での出力にも対応(`--out`)。`vuln_triage.html` に読み込める。
- **ログ確認(任意、`--log-path` または `--journalctl-unit`)**: namedのメッセージログ
  (syslog/journal)から、R22のSigmaルールと同じパターン——assertion failure特有の行
  (`INSIST(`・`REQUIRE(`・`exiting (due to fatal error)`等)が、GSS-TSIG/TKEY文脈の近く
  (前後3行以内)に現れていないかを確認する。これは「クラッシュが起きたこと」の確認であり、
  CVE-2026-94300固有の確証ではない(他のnamedクラッシュでも同じ形になりうる)。

## できないこと・正直な限界

- **厳密なセマンティックバージョン比較ではない。** namedのバージョン表記はディストリで
  バックポートされることがあり(例: RHEL系は独自のパッチレベル表記を持つ)、本ツールの
  近似照合では正確に判定できない場合がある。不明な場合は「断定しない」設計にしている
  (過去のApache 2.2.xの誤判定の教訓と同じ構図)。
- CHAOS版数バナーは運用上よく無効化される(今回のCVEとは無関係に、以前からの定番の
  ハードニング手法)ため、応答が無い/解釈できない場合でも「安全」の確証にはならない。
  また、バナーの値自体は問い合わせ先が返した値をそのまま信じるため、問い合わせ先が
  信頼できるリゾルバであることが前提(第三者が偽装したバナーを返す環境では無意味)。
- named自体のバグを検査するわけではない(動的なエクスプロイト再現は行わない)。

## 使い方

```bash
python3 scripts/bind_version_check.py
python3 scripts/bind_version_check.py --out bind_check.sarif
python3 scripts/bind_version_check.py --query 127.0.0.1 --i-own-these
python3 scripts/bind_version_check.py --log-path /var/log/syslog
python3 scripts/bind_version_check.py --journalctl-unit named
```

## 検証

- このサンドボックス環境(BIND未インストール)に対してローカルモードを実行し、
  `named`コマンドが無い場合に正しく`info`レベルで報告することを確認した。
- `assess_version()`のバージョン判定ロジックは、境界値(9.20.29/9.20.30、9.21.26/9.21.27、
  9.18.50、9.11.0、9.22.0、BIND 9系以外)を直接呼び出してユニットテストし、意図した分岐
  (`high`/`info`/`medium`)になることを確認した。
- CHAOS TXT問い合わせの組み立て・パース(`build_chaos_txt_query`/`parse_chaos_txt_reply`)は、
  合成したDNS応答パケット(圧縮ポインタでの名前参照を含む)を直接渡してユニットテストし、
  バージョン文字列("9.20.15-S1")を正しく取り出せることを確認した。
- ネットワークモード(`--query`)は、許可範囲内(127.0.0.1、応答なし→`info`で正常終了)・
  許可範囲外(拒否・終了コード2)・`--i-own-these`なし(拒否・終了コード2)の3パターンを
  このサンドボックスで実行確認した。
- **2026-10-25追記(実機検証)**: このサンドボックスに実際に`apt install bind9`でBIND9
  (9.18.39-0ubuntu0.24.04.8、Ubuntu 24.04パッケージ)を導入し、`named -u bind -g`で
  起動した状態で`--query 127.0.0.1 --i-own-these`を実行。実際に稼働しているnamedに対する
  CHAOS TXT問い合わせで`9.18.39-0ubuntu0.24.04.8-Ubuntu`という本物のバージョン文字列を
  取得し、影響範囲(9.11.0〜9.18.50)に該当する`high`判定、および9.18系がEOLでISCからの
  修正が無い旨まで正しく報告することを確認した。これにより、上記の「実際にBINDが稼働している
  リゾルバに対する応答の解析は未検証」という限界は解消された。
- ログ確認は、合成したsyslog行(assertion failure行をGSS-TSIG/TKEY文脈の近くに置いたもの、
  離して置いたもの)でユニットテストし、意図どおり前者だけ検知することを確認した。
  `--journalctl-unit named`はこのサンドボックスで実行し(named自体は存在しないため該当ログは
  0件)、エラーにならず正常終了することを確認した。実際のnamedクラッシュログでの検証は
  未実施(実機のBINDが無いため)。

> 確認・検知の設計に限定。攻撃の実行手順やエクスプロイトコードは含めない。
