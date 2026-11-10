# memory_poisoning_check: 混在ログからR32(永続メモリ汚染による二次IDPI)を確認するツール

## 経緯

2026-11-09の会話で、「Anthropicのエージェント構築ガイド群(Harnesses・CLAUDE.md+memory・
Hooks・Subagents等)はこのリポジトリで既に考慮済みか」という問いへの答えとして、
Skills(`openclaw-skill-supply-chain.ja.md`)・MCP・マルチエージェント構成は既存の整理で
拾えていたが、「永続メモリ(CLAUDE.md等)そのものへの汚染」という攻撃面は未分析だった。

> このルールは`status: experimental`で、**本リポジトリ独自の発想**によるものであり、
> 特定の実事件を報じた一次情報源は無い。R9(`r9_idpi_steered_egress.yml`、即時型IDPI)に
> 対する「二次/蓄積型IDPI」として、`sqli-lab`の`second_order_sqli`/`stored_xss`と同じ構図を
> エージェントの永続化層(CLAUDE.md・AGENTS.md・`.claude/`・`.codex/`・`.cursor/`配下の設定・
> memoryファイル)に適用したもの。

## やること(確認専用、読み取りのみ)

- 混在ログ(JSON Lines。`memory_write`・`session_start`・`egress`の3種類のイベント)を読む。
- `target_file`が既知のメモリ/設定ファイルパターン(CLAUDE.md・AGENTS.md・`.claude/`・
  `.codex/`・`.cursor/rules`・copilot-instructions.md・memory.json)に一致し、かつ
  `writer_process`が既知のエディタ(vim/nvim/nano/emacs/subl/code/pico)でない
  `memory_write`イベントを「疑わしい書き込み」とする。
- 同一hostで、その書き込みより後に発生した`session_start`を探し、そのセッションの
  最初の`egress`(既定: セッション開始から600秒以内)の宛先が許可リスト外であれば検知。
- ネットワーク通信は一切しない。ログの改変もしない。

## 使い方

```bash
python3 scripts/memory_poisoning_check.py --log-path events.jsonl
python3 scripts/memory_poisoning_check.py --log-path events.jsonl --allowlist-suffix api.openai.com --trigger-window-seconds 300
```

終了コード: 0(ヒット無し) / 1(ヒット有り) / 2(ログ読み取り失敗)。

## 確認したこと(2026-11-10、このサンドボックス内)

- 合成ログ(`/usr/bin/node`がCLAUDE.mdへ書き込み→後続セッションの初回egressが
  `evil.example.net`へ、という陽性パターン / `/usr/bin/vim`による正規の書き込み→後続
  セッションの初回egressが許可リスト内`api.openai.com`へ、という陰性パターン)で、
  陽性のみを正しく検出。誤検知0件を確認した。
- `scripts/run_detection_regression.py`経由でCI回帰にも組み込み済み(他17本の検知
  スクリプトと同じ扱い)。

## 確認していないこと

- 実際のAIコーディングエージェント(Claude Code・Codex・Cursor等)が出力する**本物の**
  ファイルイベント/セッションログでの動作(今回はすべて合成ログでの検証)。各ツールが
  実際にどのようなログ形式・フィールド名でファイル書き込み・セッション開始・egressを
  記録するかは未調査で、本スクリプトが想定する単純化されたスキーマと異なる可能性が高い。
- 「後続セッションの最初のegress」という判定条件自体、実際のエージェントがCLAUDE.md等の
  内容をどう「標準的な指示」として扱い、どのタイミングで最初のツール呼び出し/通信を
  行うかという、実際のハーネス実装の挙動の裏取りは無い(本リポジトリ独自の仮説)。
- セッション開始から最初のegressまでの時間窓(既定600秒)は、Sigmaルールのコメントに
  書いた目安であり、実際のベースラインから導出したものではない。
- `writer_process`が「既知のエディタでない」ことを「疑わしい」とする判定は、スクリプト・
  自動化ツール・CI等、正規の非エディタプロセスによる書き込みも拾ってしまう誤検知の
  余地がある(許可リストでのチューニングが前提)。

> 確認・検知の設計に限定。攻撃の実行手順や安全機構の回避方法は含めない。
