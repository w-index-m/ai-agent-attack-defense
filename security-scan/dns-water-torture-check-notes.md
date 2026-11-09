# dns_water_torture_check: DNSクエリログから R12 を確認するツール

## 経緯

`verification-gates.md`の棚卸しで見つかったギャップの1つ。`security-scan/detections/sigma/
r12_dns_water_torture.yml`は、「単一の登録ドメイン配下で、多数の異なる(疑似ランダムな)
サブドメインへの問い合わせが、短時間に急増する」というDNS水攻め/ランダムサブドメイン攻撃の
**ルール定義**で、投入先はSIEM側が前提。`scripts/dns_water_torture_check.py`は、このルールを
再帰リゾルバの実クエリログに対して直接実行する版。

## やること(確認専用、読み取りのみ)

- JSON Lines形式のDNSクエリログを読む(`dns_query`/`query`/`qname`のいずれかと、
  `dns_answer`/`answer`/`rcode`のいずれか)。
- クエリを「登録ドメイン」(簡易eTLD+1。最後の2ラベルを登録ドメインとみなす、複合TLD非対応と
  明記のうえの割り切り)単位でグループ化。
- タイムスタンプを時間窓(既定60秒、`--window-seconds`で変更可)に丸め、登録ドメイン×時間窓
  ごとに「異なるサブドメイン数」と「NXDOMAIN率」を計算。
- 異なるサブドメイン数が閾値(既定200、`--subdomain-threshold`)を超え、かつNXDOMAIN率が
  閾値(既定80%、`--nxdomain-ratio`)を超える場合に検知(Sigmaルールのコメントに書かれた
  集計方針そのまま)。
- ネットワーク通信は一切しない。ログの改変もしない。

## 使い方

```bash
python3 scripts/dns_water_torture_check.py --log-path dns.jsonl
python3 scripts/dns_water_torture_check.py --log-path dns.jsonl --subdomain-threshold 50 --nxdomain-ratio 0.5
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-08、このサンドボックス内)

- 合成DNSクエリログで、単一の登録ドメイン(`victim.example`)配下に250件の異なるランダム
  サブドメイン、全てNXDOMAIN・同一時間窓、を正しく検知。
- 同じログ内の`legit-cdn.example`(250件の異なるサブドメインだが全てNOERROR応答)は、
  NXDOMAIN率が閾値未満のため誤検知0件(高カーディナリティなCDN等を想定した陰性対照)。
- `--allowlist-suffix victim.example`で指定すると、該当ドメインが正しく除外されることを確認。
- **テスト設計上の注意(自分の失敗から)**: 最初、各クエリのタイムスタンプを1秒ずつ増やして
  いったところ、250件が複数の60秒窓にまたがってしまい、閾値未満と誤判定された。時間窓の
  境界を意識しないと、本当は閾値を超えているはずのバーストが分散されて見逃される、という
  落とし穴がある(このツール固有の問題ではなく、固定時間窓での集計一般に言えること)。

## 確認していないこと

- 実際に稼働している再帰DNSリゾルバ(BIND・Unbound・PowerDNS等)が出力する**本物の**クエリ
  ログでの動作(今回はすべて合成ログでの検証)。ログの出力形式・フィールド名は製品ごとに
  大きく異なるため、JSON Linesへの変換が別途必要になる可能性が高い。
- 簡易eTLD+1抽出は、`.co.jp`のような複合TLDを正しく扱えない(例: `foo.example.co.jp`を
  `co.jp`ではなく誤って判定しうる)。公開サフィックスリスト(Public Suffix List)を使った
  厳密な実装は未対応。
- 大規模ログ(GB単位)での性能(全行をメモリに読み込む実装)。

## 2026-11-08追記: R12はGate 2に留める(訂正あり)

`verification-gates.md`の棚卸しで、R12が参照する`https://www.us-cert.gov/ncas/alerts`を
WebSearchで確認したところ、この技術に関する具体的なアドバイザリには解決しなかった
(汎用的なポインタであり、具体的なURLではなかった)。また、R12が模す「DNS水攻め」は特定の
1件の事件ではなく数十年来の汎用技術(2016年のDyn DNS攻撃が代表例として広く引用される)で
あるため、そもそも他のルールのような「特定事件の一次情報裏取り」という枠組みが当てはまり
にくい。無理にGate 3と名乗らず、Gate 2のまま、参照の不備を正直に訂正した。


## 2026-11-09追記: CI回帰に組み込んだ

これまで「このセッション内で一度、合成ログで動作確認した」のみで、継続的な再検証の手段が
無かった。`security-scan/detection-fixtures/`に陽性/陰性の合成ログを同梱し、
`scripts/run_detection_regression.py`が`.github/workflows/security-scan.yml`の`scan`
ジョブから毎回(PR・push・毎日の定期実行)このスクリプトを実行し、陽性入力は必ず検知・
陰性入力は必ず誤検知0件であることを確認するようになった。壊れた場合は
`results/detection_regression.json`に記録され、`scripts/summarize.py`経由でCIの要約にも
出る。詳細は`scripts/run_detection_regression.py`自身のdocstring参照。
