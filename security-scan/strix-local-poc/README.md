# Strix ローカル実行 PoC（Docker 不要）

[usestrix/strix](https://github.com/usestrix/strix) v1.7.0 を Docker デーモンなしで
ホスト上で動かす PoC の成果物。設計の全体像は
[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md) を参照。

> ⚠️ Strix は認可されたペネトレーションテスト用ツール。対象は自分が所有・許可を得たものだけに限定すること。

## ファイル

| ファイル | 内容 |
|---|---|
| `strix-local-backend.patch` | strix に当てる 2 箇所（~40 行）の差分。`local` バックエンド追加＋Docker 事前チェックのゲート。 |
| `poc_local_backend.py` | LLM 非依存の検証スクリプト。`local` バックエンドでセッション起動→ホスト実行→ソース materialize を確認。 |

## 再現手順

```bash
# 1) strix を取得して依存を入れる
git clone https://github.com/usestrix/strix
cd strix && uv sync

# 2) パッチを当てる
git apply /path/to/strix-local-backend.patch

# 3a) バックエンド直接検証（LLM 不要）
#     poc_local_backend.py 内の SRC_REPO を解析対象に合わせて編集してから:
uv run python /path/to/poc_local_backend.py

# 3b) 実 CLI（要 LLM API キー。対象ディレクトリで実行）
export STRIX_RUNTIME_BACKEND=local
export STRIX_LLM="anthropic/claude-sonnet-5-5"   # LiteLLM の model id
export LLM_API_KEY="<有効なキー>"
uv run strix -n -t ./ --scan-mode quick --max-budget 10
```

## 要点（詳細は設計メモ）

- `local` バックエンドは SDK 同梱の `UnixLocalSandboxClient` を使い、ホスト上で直接実行。
- `LocalDir` 展開は CWD 配下のソースのみ許可（`-t ./` なら常にOK）。
- 外部ツール（nmap/ffuf/caido/playwright）はホストに未同梱 → コード解析系に限定するのが無難。
- コンテナ隔離が無くなる点に注意。
