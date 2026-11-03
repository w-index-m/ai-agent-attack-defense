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
| `mock_llm_server_chain.py` | 検証7。単発脆弱性ではなく、SSRF(`/fetch_url`)→IDOR(`/idor_login`→`/idor_account`)という2段階の攻撃連鎖を1回のスキャンで再現する台本。途中で、1手目のツール呼び出し結果が後続の会話コンテキストから欠落するというStrix側の挙動を発見・再現確認した。詳細は[`../strix-local-backend-notes.md`](../strix-local-backend-notes.md)の「検証7」参照。 |

## 再現手順

```bash
# 1) strix を取得して依存を入れる
git clone https://github.com/usestrix/strix
cd strix && git checkout v1.7.0   # パッチはv1.7.0専用。最新(main)には当たらない
uv sync

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

## `vuln_triage.html`のGUIボタンから起動する(`scripts/local_scan_server.py`経由)

上記3c)の手順(clone・パッチ適用・`uv sync`)を済ませたStrixの作業コピーがあれば、ブラウザの
`vuln_triage.html`から「Strixを実行」ボタンで直接起動できる。詳細は
[`../local-scan-server-notes.md`](../local-scan-server-notes.md)参照。

```bash
# 事前準備(初回だけ、上記3c)と同じ)
git clone https://github.com/usestrix/strix /path/to/strix
cd /path/to/strix
git checkout v1.7.0   # パッチはv1.7.0専用。最新(main)には当たらない
git apply /path/to/strix-local-backend.patch
uv sync

# local_scan_server.py を起動する前に、作業コピーのパスを指定
export STRIX_LOCAL_DIR=/path/to/strix
python3 scripts/local_scan_server.py
```

`vulnerable_app.py`・`mock_llm_server.py`はまだ起動していなければ、`/scan/strix`エンドポイント
自身が自動で起動する(手動で先に立ち上げておく必要はない)。GUI側は、能動的にこのリポジトリ自身の
`sqli-lab`デモアプリへ攻撃ペイロードを送ることへの同意チェックボックスを明示的に要求する。結果は
`findings.sarif`として返り、`vuln_triage.html`の既存SARIF取り込みにそのまま乗る。

### Windowsの場合: 画面はWindows、StrixだけWSL2のサーバーで動かす

`local`バックエンドはOpenAI Agents SDKの`UnixLocalSandboxClient`(Unix専用)を使うため、Windows上で
起動した`local_scan_server.py`ではStrixを実行できない(2026-11-02に実機で`run.json`の`status`が
`failed`になることを確認)。そのため、Windows上のサーバーで「Strixを実行」を押すと、数分待たずに
すぐ理由と手順をエラー表示する(起動時のメッセージと自己診断にも表示される)。

`vuln_triage.html`はブラウザで開くただのページで、ボタンを押すと、接続設定に書いたURLへHTTPで
要求を送るだけ。サーバーがどこで動いているかは問わないので、**画面はWindowsのブラウザのまま、Strix
だけWSL2で起動したサーバーに送る**ことができる。WSL2で起動したサーバーには、Windowsのブラウザから
通常`localhost`で接続できる(WSL2の既定の機能)。

1. いつも通り、Windows(PowerShell)で`python scripts\local_scan_server.py`を起動する(ポート8766。
   Semgrep・Trivy・gitleaks・netcheck・Cairn等はこちら)。
2. WSL2(Ubuntu)のターミナルで、2つ目のサーバーをポート8767で起動する。作業フォルダはWSL側に
   cloneするのがおすすめ(`/mnt/c/...`のWindows側フォルダより速い)。

   ```bash
   # 初回だけ
   curl -LsSf https://astral.sh/uv/install.sh | sh
   git clone https://github.com/w-index-m/ai-agent-attack-defense ~/ai-agent-attack-defense
   git clone https://github.com/usestrix/strix ~/strix
   cd ~/strix && git checkout v1.7.0
   git apply ~/ai-agent-attack-defense/security-scan/strix-local-poc/strix-local-backend.patch
   uv sync

   # 毎回
   cd ~/ai-agent-attack-defense && git pull
   STRIX_LOCAL_DIR=~/strix VULN_APP_PORT=5100 VULN_INTERNAL_PORT=5101 \
     python3 scripts/local_scan_server.py --port 8767
   ```

   `VULN_APP_PORT=5100`は、WSL2の「ミラーモード」でWindowsとポートを共有している場合に、Windows側で
   5000/5001を使っている常駐ソフトとぶつからないようにするため(ぶつからない環境なら省略可)。
3. `vuln_triage.html`の「接続設定」で、「Strix用エンドポイント」に`http://localhost:8767`を入れる
   (この端末に保存される)。以後、「Strixを実行」だけがWSL2のサーバーへ送られ、他のボタンは
   これまで通りWindowsのサーバー(8766)へ送られる。

監査ログはポートごとに別ファイル(8767は`results/local-scan/audit-8767.jsonl`)。同じファイルに
2つのサーバーが同時に書くと番号が重複して検証がNGになることを、テストで確認したため。

確認状況: 2026-11-03に、Windows 11+WSL2(Ubuntu)の実機で、この手順どおりにStrixを実行し、SQLi認証
バイパスの指摘を画面に取り込めた(Windowsのブラウザから`localhost:8767`でWSL2のサーバーへ届くことも
確認)。手順2のコマンドは、PowerShellではなく、`wsl`と入力して入ったUbuntuの中で実行する。古いサーバーが
動いたままだと`Address already in use`になるので、`pkill -f "local_scan_server.py --port 8767"`で止めてから
起動する。

既定では`sqli-lab`デモアプリはポート5000(内部ポート5001)で起動する。Windows環境で、ウイルス対策
ソフトなどの常駐プロセスがこのポートを既に専有していて起動に失敗する場合は、`local_scan_server.py`を
起動する前に環境変数`VULN_APP_PORT`で変更できる(例: PowerShellで`$env:VULN_APP_PORT="5100"`)。

## 要点（詳細は設計メモ）

- `local` バックエンドは SDK 同梱の `UnixLocalSandboxClient` を使い、ホスト上で直接実行。
- `LocalDir` 展開は CWD 配下のソースのみ許可（`-t ./` なら常にOK）。
- caido はバックエンド単位でゲート。`local` では caido を起動せず proxy ツールは「利用不可」に degrade。
- 外部ツール（nmap/ffuf/playwright）はホストに未同梱 → コード解析系に限定するのが無難。
- コンテナ隔離が無くなる点に注意。
