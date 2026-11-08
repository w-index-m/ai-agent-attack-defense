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

## 確認していないこと

- 実際のauditd/Sysmon等が出力する**本物の**ネットワーク接続ログでの動作(今回はすべて合成ログ
  での検証)。
- 「受信直後に」という、Sigmaルールが本来含意する時間的な前後関係(inbound requestの直後の
  outbound接続)は、本スクリプトでは判定していない(接続イベント単体のみで判定)。
