# web_recon_burst_check: Webアクセスログから R3 を確認するツール

## 経緯

`verification-gates.md`の棚卸し(R1-R31をGate 0〜2で分類)で、「R3(偵察的Webアクセス、
列挙バースト)を実際のWebアクセスログに対して実行する独立ツールが無い」という既知のギャップが
あり、2026-11-08にこれを埋めた。

`security-scan/detections/sigma/r3_recon_enumeration_burst.yml`は、「管理画面系パスへの
401/403/404応答が、同一送信元IPから短時間(1分)に30件超」というパターンの**ルール定義**で、
投入先はSIEM側が前提。`scripts/web_recon_burst_check.py`は、このルールをWebサーバーの実
アクセスログに対して直接実行する版。

## やること(確認専用、読み取りのみ)

- Apache/Nginxの標準combined log形式、またはJSON Lines形式のアクセスログを読む。
- 管理画面系パス(`/admin`・`/wp-login.php`・`/wp-admin/`・`/phpmyadmin/`・`/console`等、
  Sigmaルールと完全に同じ一覧)への、401/403/404応答のリクエストだけを対象にする。
- タイムスタンプを分単位(既定60秒、`--window-seconds`で変更可)の時間窓に丸め、
  (送信元IP, 時間窓)ごとに件数を集計。閾値(既定30件、`--threshold`で変更可、Sigmaルールの
  `> 30`と同じ)を超えたものを検知として報告。
- ネットワーク通信は一切しない。ログの改変もしない。

## 使い方

```bash
python3 scripts/web_recon_burst_check.py --log-path /var/log/nginx/access.log
python3 scripts/web_recon_burst_check.py --log-path access.jsonl --format jsonl --threshold 10
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-08、このサンドボックス内)

- Apache/Nginx combined log形式の合成ログで、単一IP(`203.0.113.5`)から同一分内に35件の
  管理画面系パス列挙(ツール名`ffuf/2.0`を模したUser-Agent)を正しく検出。別のIP
  (`198.51.100.9`、10件・閾値未満)・無関係な正常アクセス(200応答)では誤検知0件。
- JSON Lines形式の合成ログで、32件の列挙を正しく検出。

## 2026-11-08追記: R18(PHPUnit eval-stdin.php)・R19(ThinkPHP invokefunction)を追加

「gate0止まりのしょり」の指示で、`r18_phpunit_eval_stdin_rce.yml`・`r19_thinkphp_invokefunction_rce.yml`
を追加した。どちらも`status: stable`(確定済みの脆弱性パターン)で、R3と同じWebアクセスログの
URIへの単純な文字列一致(閾値・時間窓は不要、1件でも即検知)。

合成ログ(PHPUnitパスへのリクエスト1件・ThinkPHPのinvokefunction+call_user_func_arrayを含む
リクエスト1件・無関係な正常リクエスト1件)で正しく検出し、誤検知0件を確認。

## 2026-11-08追記2: R18・R19のCVE記述をWebSearchで再確認(軽微、Gate 3は元から到達済み)

R18・R19は元から`status: stable`で、NVD/CISA KEVという一次情報源を直接引用済み(R20・R27-R31の
ような「二次情報源経由の報道ベース」ではない)。念のためWebSearchで再確認した結果:

- **CVE-2017-9841**(R18): CVSS 9.8(Critical)、CISA KEV登録(2022-02-15追加)。ルール記述
  と一致。
- **CVE-2018-20062**(R19): CVSS 9.8(Critical)、CISA KEV登録(2021-11-03追加)。ルール記述
  と一致。ただしKEVエントリ自体は「ThinkPHP noneCms」という名称で登録されており、脆弱な
  コンポーネントの呼び方(ThinkPHP本体 vs noneCms)について情報源間で表記が一致していない点に
  注意。

いずれも記述の訂正は不要だった。R18・R19は元からGate 3相当の裏取りが済んでいたことを確認できた
のみ。

## 確認していないこと

- 実際に稼働しているApache/Nginxが出力する**本物の**アクセスログでの動作(今回はすべて
  合成ログでの検証)。`LogFormat`のカスタマイズ次第で、標準combined形式と異なる場合がある。
- 大規模ログ(GB単位)での性能(全行をメモリに読み込む実装)。
- タイムゾーンを含むタイムスタンプの厳密な扱い(`_parse_apache_time`はタイムゾーン部分を
  無視して分単位の粒度で丸めており、タイムゾーンをまたぐログの境界では誤差がありうる)。

## 2026-11-08追記3: R3をGate 3に区分(`verification-gates.md`棚卸しとの整合)

R3は、Gambit Securityが自社で発見・回収した攻撃者ステージングサーバーに基づく一次報告
(2026-09-22)を出典としており、Gambit自身の一次情報源にあたる。直接fetchはブロックされて
いるため、複数の独立した二次情報源の一致した報告で確認した。これによりR3をGate 3に区分
した。検知ロジック自体(閾値・時間窓による集計)は本リポジトリ独自の構成のままである。


## 2026-11-09追記: CI回帰に組み込んだ

これまで「このセッション内で一度、合成ログで動作確認した」のみで、継続的な再検証の手段が
無かった。`security-scan/detection-fixtures/`に陽性/陰性の合成ログを同梱し、
`scripts/run_detection_regression.py`が`.github/workflows/security-scan.yml`の`scan`
ジョブから毎回(PR・push・毎日の定期実行)このスクリプトを実行し、陽性入力は必ず検知・
陰性入力は必ず誤検知0件であることを確認するようになった。壊れた場合は
`results/detection_regression.json`に記録され、`scripts/summarize.py`経由でCIの要約にも
出る。詳細は`scripts/run_detection_regression.py`自身のdocstring参照。
