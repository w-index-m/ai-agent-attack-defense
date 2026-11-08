# auth_proxy_rotation_check: 認証ログからR30を確認するツール

## 経緯

`verification-gates.md`の棚卸しで見つかったギャップ。`security-scan/detections/sigma/
r30_multi_egress_ip_proxy_rotation.yml`は、「単一アカウント/セッションが、短時間に多数の
異なる送信元IPから認証する」というプロキシローテーション基盤の兆候の**ルール定義**で、
投入先はSIEM側が前提。`scripts/auth_proxy_rotation_check.py`は、同じ判定ロジックを認証ログ
に対して直接実行する版。

> このルールは`status: experimental`で、「報道ベース(Hunt.io)で、韓国7金融機関への侵害基盤
> との直接の関係は未確認」と明記されている。スクリプト化してもこの限界は残る。

## やること(確認専用、読み取りのみ)

- 認証イベントのログ(JSON Lines)を読む。
- アカウント/セッション単位でグループ化し、異なる送信元IP数が閾値(既定10件)を超えた場合に
  検知。
- ネットワーク通信は一切しない。

## 使い方

```bash
python3 scripts/auth_proxy_rotation_check.py --log-path auth.jsonl
python3 scripts/auth_proxy_rotation_check.py --log-path auth.jsonl --threshold 5
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-08、このサンドボックス内)

- 合成ログ(account-Aが15個の異なるIPから認証・account-Bが5個のみ)で、閾値(既定10件)超の
  account-Aのみを正しく検出。閾値未満のaccount-Bは誤検知0件。

## 確認していないこと

- 実際の認証基盤(SSO・VPN・Webアプリのログイン等)が出力する**本物の**認証ログでの動作
  (今回はすべて合成ログでの検証)。
- 時間窓(既定600秒)は、タイムスタンプが連続したログでは厳密なスライディングウィンドウでは
  なく、同一アカウントの全イベントを1つの集合として数える簡略化をしている(他のスクリプトと
  同じ割り切り)。
- ASN/地理的位置情報を使った「複数IPが地理的に矛盾しているか」の判定は未実装(Sigmaルールの
  コメントが挙げる追加条件)。
