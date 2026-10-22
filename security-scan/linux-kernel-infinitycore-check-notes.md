# Linux カーネル「Infinity Core」確認（確認専用）

`scripts/linux_kernel_infinitycore_check.py`: 実行中のLinuxカーネル(`uname -r`)と
`/etc/os-release` を、「Infinity Core」——研究者 Hyunwoo Kim(V4bel)が2026-10-16、
ディストリビューション向けエンバーゴ終了後に公開した、6件のLinuxカーネルローカル権限
昇格(LPE)脆弱性チェーン(主要CVE-2026-98260ほか、[`detections/`](detections/) の R21 参照)
——の対象になりうるかを確認する。

> ⚠️ 方針：**確認専用**。カーネルの更新、設定変更、ネットワークへの接続は一切しない。
> 実行するのは、そのホストの `uname`/`/etc/os-release` の読み取りだけ。

## 背景: Infinity CoreとR21の関係

R21(`detections/sigma/r21_infinitycore_kernel_lpe.yml` 等)は、「カーネルエクスプロイト自体は
ユーザー空間に決まったログの痕跡を残さない」という前提で作った、結果側(非特権プロセスが
既知の昇格経路なしにroot(UID 0)へ遷移する)からの探索的ヒューリスティック。本スクリプトは
それを補完する、ホスト側の**バージョン確認**ツール: 「このホストのカーネルはそもそも
Infinity Coreの対象バージョン範囲にあるか」を調べる。

timer・signal・メモリ管理・futex・scheduler・SLUB/SLABの6箇所のカーネルバグで、5件がroot
権限昇格の公開PoCあり(GitHub `V4bel/InfinityCore`)。回避策(sysctl等)は無く、カーネル
更新+再起動のみが対処。

## できること

- `uname -r`(カーネルリリース文字列)と `/etc/os-release`(ディストリビューションと
  バージョン)を表示。
- CloudLinux CL9の場合のみ、CloudLinux公式ブログで判明している正確な修正済みビルド
  (`5.14.0-687.59.1.el9_8`)との一致を確認。
- SARIF 2.1.0 での出力にも対応(`--out`)。`vuln_triage.html` に読み込める。

## できないこと・正直な限界

- **CloudLinux CL9以外のディストリビューションでは、「脆弱/安全」を断定しない。**
  ディストリビューションごとにバックポートされたカーネルのバージョン表記がバラバラなため、
  単純な数値比較は誤判定を招く(過去にApache 2.2.xのバージョン範囲誤判定で学んだ教訓と同じ
  構図)。CloudLinux CL9以外では、実行中のバージョン・ディストリビューション情報を表示する
  だけで、最終判断は各ディストリビューションの公式セキュリティアドバイザリに委ねる。
- CloudLinux CL9の比較も、「このビルド文字列と完全一致するか」だけの判定。ディストリビューション
  側がビルド番号を更に更新した場合は、このツールのハードコードされた文字列が古くなる可能性がある。
- カーネルのバグそのものを検査するわけではない(動的なエクスプロイト再現は行わない)。

## 使い方

```bash
python3 scripts/linux_kernel_infinitycore_check.py
python3 scripts/linux_kernel_infinitycore_check.py --out infinitycore.sarif
```

## 検証

- このサンドボックス環境(Ubuntu 24.04.5、カーネル `6.18.44-fc-v140`)に対して実行し、
  動作を確認した: CloudLinuxではないため断定せず、ディストリビューション情報とともに
  公式アドバイザリ確認を促す出力になることを確認。
- CloudLinux CL9の比較ロジック(`assess()`内の文字列一致判定)は、修正済みビルド文字列と
  一致する場合・一致しない場合の両方を直接呼び出してユニットテストし、いずれも意図した
  分岐(`info`/`high`)になることを確認した(このサンドボックス自体はCloudLinuxではないため、
  実機でのCloudLinux CL9環境での動作は未検証)。

> 確認・検知の設計に限定。攻撃の実行手順やエクスプロイトコードは含めない。
