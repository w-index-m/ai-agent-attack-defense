# Strix ローカル実行 PoC（Docker 不要）

[usestrix/strix](https://github.com/usestrix/strix) v1.7.0 を Docker デーモンなしで
ホスト上で動かす PoC の成果物。設計の全体像は
[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md) を参照。

> ⚠️ Strix は認可されたペネトレーションテスト用ツール。対象は自分が所有・許可を得たものだけに限定すること。

## ファイル

| ファイル | 内容 |
|---|---|
| `strix-local-backend.patch` | strix に当てる 3 ファイルの差分。`local` バックエンド追加＋Docker 事前チェックのゲート＋caido 結合のバックエンド単位ゲート。 |
| `poc_local_backend.py` | LLM 非依存の検証1。`local` バックエンドでセッション起動→ホスト実行→ソース materialize を確認。 |
| `poc_caido_free.py` | LLM 非依存の検証3。`create_or_reuse(backend=local)` が caido 非依存で完走し、`caido_client=None`・proxy env 未注入を確認。 |
| `mock_llm_server.py` | 検証4・5。実LLMキー不要の、OpenAI互換モックLLMサーバー。疎通確認(非ストリーミング)には`OK`、本番ループ(ストリーミング)には台本どおりのツール呼び出し(`exec_command`→`create_vulnerability_report`→`finish_scan`)を返し、Strixをエンドツーエンドで完走させる。`exec_command`は`security-scan/sqli-lab`の`/login`SQLiバイパスを実際にcurlで再現し、その結果を`create_vulnerability_report`に実データとして渡す。詳細は[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md)の「検証4」「検証5」参照。 |
| `mock_llm_server_deserialize.py` | 検証6。`mock_llm_server.py`の台本を書き換えた別シナリオ。脆弱性クラスをSQLiから`/deserialize`の安全でないデシリアライゼーション(pickle)→RCEに差し替え、ターン数も2段階→5段階(ペイロード作成→送信→確認→レポート提出→終了)に増やしている。台本(ツール名・引数・ターン数)が自由に差し替え可能であることの実証。詳細は[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md)の「検証6」参照。 |

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

# 3a') caido 非依存の検証（LLM 不要）
uv run python /path/to/poc_caido_free.py

# 3b) 実 CLI（要 LLM API キー。対象ディレクトリで実行）
export STRIX_RUNTIME_BACKEND=local
export STRIX_LLM="anthropic/claude-sonnet-5-5"   # LiteLLM の model id
export LLM_API_KEY="<有効なキー>"
uv run strix -n -t ./ --scan-mode quick --max-budget 10

# 3c) 実 CLI、ただし実 LLM キー不要（モックLLMでエンドツーエンド完走、検証4・5）
#     対象ディレクトリを ./ とし、sqli-lab の vulnerable_app.py を VULN_APP_HOST=127.0.0.1 で
#     先に起動しておくと、台本が実際にSQLi認証バイパスを再現してレポートに反映する。
python3 /path/to/mock_llm_server.py 8899 &
export STRIX_RUNTIME_BACKEND=local
export STRIX_LLM="openai/mock-model"
export OPENAI_API_BASE="http://127.0.0.1:8899/v1"
export OPENAI_API_KEY="dummy-mock-key"
uv run strix -n -t ./ --scan-mode quick --max-budget 10
```

## 要点（詳細は設計メモ）

- `local` バックエンドは SDK 同梱の `UnixLocalSandboxClient` を使い、ホスト上で直接実行。
- `LocalDir` 展開は CWD 配下のソースのみ許可（`-t ./` なら常にOK）。
- caido はバックエンド単位でゲート。`local` では caido を起動せず proxy ツールは「利用不可」に degrade。
- 外部ツール（nmap/ffuf/playwright）はホストに未同梱 → コード解析系に限定するのが無難。
- コンテナ隔離が無くなる点に注意。
