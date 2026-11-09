# jndi_rce_check: ネットワーク接続ログからR29を確認するツール

## 経緯

`verification-gates.md`の棚卸しで見つかったギャップ。`security-scan/detections/sigma/
r29_jndi_ldap_rce_attempt.yml`は、「Java/Tomcatのプロセスが、LDAP(389/636)・RMI(1099)
ポートへの新規アウトバウンド接続を行う」というJNDIインジェクション(Log4Shell、
CVE-2021-44228等)の典型パターンの**ルール定義**で、投入先はSIEM側が前提。`scripts/jndi_rce_check.py`
は、同じ判定ロジックをネットワーク接続ログに対して直接実行する版。

> このルールは`status: experimental`で、「報道ベース(Hunt.io)で、韓国7金融機関への侵害基盤
> との直接の関係は未確認」と明記されている。スクリプト化してもこの限界は残る。

## やること(確認専用、読み取りのみ)

- ネットワーク接続イベントのログ(JSON Lines)を読む。
- プロセスイメージが`/java`・`/tomcat`・`/catalina.sh`で終わり、かつ宛先ポートが
  389・636・1099のいずれかである接続を検知。`--allowlist-suffix`で正規のLDAP/ADサーバーを
  除外可能。
- ネットワーク通信は一切しない。

## 使い方

```bash
python3 scripts/jndi_rce_check.py --log-path connections.jsonl
python3 scripts/jndi_rce_check.py --log-path connections.jsonl --allowlist-suffix ldap.internal.example
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-08、このサンドボックス内)

- 合成ログ(javaプロセスから不審な宛先への接続1件・javaプロセスから許可リスト指定で除外される
  LDAP接続1件・nginxプロセスからの接続1件)で、許可リスト無しでは2件、許可リスト指定時は1件
  (不審な宛先のみ)を正しく検出。nginxプロセスの接続は常に対象外。

## 2026-11-08追記: 一次情報源での裏取り(Gate 3へ)

Hunt.io(2026-11-04)の報告について、WebSearchでの追加調査により以下を確認できた:

- 別の露出ディレクトリ(`23.248.226.250:8001`)で、**UnboundID LDAP SDK**を使った自己完結型の
  JNDI/LDAP悪用一式が見つかっており、DNSコールバックでコマンド実行が確認されている
  (ペイロード取得: 2026-10-05 03:42 UTC)。これはルールが想定する技術そのものの実在を補強する。
- ただし、二次情報源の報道では「LDAP」以上の具体的なポート番号(389/636/1099)は言及されておらず、
  本ルール・本スクリプトのポート選定は、Hunt.ioが公表した値ではなく、JNDI攻撃の標準的な実装
  パターンに基づく本リポジトリ独自の仮定である。
- CrowdStrikeが(二次情報源経由で)この侵害を中国系アクターに帰属させたとの報道があり、これは
  Hunt.io自身の「ARTEXコンソール→リレーサーバー」という推論とは独立した帰属経路。韓国警察による
  確定はまだ無い。

これにより`r29_jndi_ldap_rce_attempt.yml`の`description`を更新した。

## 確認していないこと

- 実際のauditd/Sysmon等が出力する**本物の**ネットワーク接続ログでの動作(今回はすべて合成ログ
  での検証)。
- 「受信直後に」という、Sigmaルールが本来含意する時間的な前後関係(inbound requestの直後の
  outbound接続)は、本スクリプトでは判定していない(接続イベント単体のみで判定)。
- ポート389/636/1099という本スクリプトの判定条件自体が、Hunt.ioの報告で直接確認された値では
  ない(上記の追記を参照)。


## 2026-11-09追記: CI回帰に組み込んだ

これまで「このセッション内で一度、合成ログで動作確認した」のみで、継続的な再検証の手段が
無かった。`security-scan/detection-fixtures/`に陽性/陰性の合成ログを同梱し、
`scripts/run_detection_regression.py`が`.github/workflows/security-scan.yml`の`scan`
ジョブから毎回(PR・push・毎日の定期実行)このスクリプトを実行し、陽性入力は必ず検知・
陰性入力は必ず誤検知0件であることを確認するようになった。壊れた場合は
`results/detection_regression.json`に記録され、`scripts/summarize.py`経由でCIの要約にも
出る。詳細は`scripts/run_detection_regression.py`自身のdocstring参照。
