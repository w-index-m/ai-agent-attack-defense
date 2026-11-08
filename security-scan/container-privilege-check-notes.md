# container_privilege_check: コンテナイベントログからR2を確認するツール

## 経緯

`verification-gates.md`の棚卸しで見つかったギャップの1つ。`security-scan/detections/sigma/
r2_privileged_container_spawn.yml`は、「NET_RAW/NET_ADMINケイパビリティ付与・privileged実行・
hostネットワーク名前空間への参加」というパターンの**ルール定義**で(ルール自体に「Falcoの方が
自然な一次情報源」と明記されている)、投入先はSIEM/Falco側が前提。`scripts/container_privilege_check.py`
は、同じ判定ロジックを、Dockerのコンテナイベントログ(`docker events --format '{{json .}}'`等)
に対して直接実行する版。

## やること(確認専用、読み取りのみ)

- コンテナランタイムのイベントログ(JSON Lines)を読む。
- `capabilities`に`CAP_NET_RAW`/`CAP_NET_ADMIN`が含まれる、`privileged`が真、または
  `network_mode`が`host`のいずれかに一致するコンテナ起動を検知。
- ネットワーク通信・コンテナの起動停止は一切しない。

## 使い方

```bash
python3 scripts/container_privilege_check.py --log-path container_events.jsonl
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-08、このサンドボックス内)

- 合成ログ(特権ケイパビリティ付き1件・privileged実行1件・hostネットワーク1件・無関係な
  nginxコンテナ1件)で、3件を正しく検出し、無関係なコンテナでは誤検知0件。

## 確認していないこと

- 実際のDocker/containerd/Falcoが出力する**本物の**イベントログでの動作(今回はすべて
  合成ログでの検証)。実際のDockerイベントのJSON構造(`Actor.Attributes`のネスト等)と、
  本スクリプトが想定するフラットなキー名が一致しない可能性がある。
