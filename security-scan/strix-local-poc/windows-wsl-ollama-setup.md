# Windows 11 + WSL2 + Ollama で Strix をローカルLLMだけで動かす手順(実機メモ)

対象: 自分が所有する Windows 11 機で、クラウドLLM課金なしに Strix (v1.7.0) を試す場合の
実機セットアップ手順。`strix-local-backend-notes.md` の「ローカルLLM」部分の、実際に踏んだ手順の記録。

> ⚠️ 対象は自分が所有・管理するローカル環境(自作ソフト、または DVWA/Juice Shop のような
> 自分で立てた練習用環境)に限定すること。Strix はペネトレーションテスト用ツールであり、
> 許可のない対象への実行は行わないこと。

## 前提

- Windows 11、WSL2 (Ubuntu)
- Docker Desktop(WSL2 バックエンド)
- Ollama for Windows(GUI 版)に、ツール呼び出し対応の小型モデル(例: `qwen2.5:1.5b`)を導入済み

## 1. OllamaをWSL側から到達可能にする

既定では Ollama は `127.0.0.1` のみで待ち受けるため、WSL2(別ネットワーク名前空間)から到達できない。

Windows 側(PowerShell、新規ウィンドウ)で環境変数を設定:

```powershell
setx OLLAMA_HOST "0.0.0.0:11434"
```

`setx` は新規プロセスにしか反映されないため、**Ollamaアプリを完全終了してから**、新しい
PowerShellで起動し直す:

```powershell
echo $env:OLLAMA_HOST   # 0.0.0.0:11434 になっているか確認
ollama serve
```

ログに `Listening on [::]:11434` が出れば待ち受け成功。このウィンドウは閉じずに開いたままにする。

## 2. WSL側からWindowsホストへの到達性を確認する

WSL2 の `localhost` 自動転送は環境によって効かないことがある。効かない場合は、WSLから見た
Windowsホストの実IPを使う。

```bash
# まず localhost を試す
curl http://localhost:11434/api/tags

# ダメなら、WindowsホストのIPを調べる(ip route の方が確実)
ip route show | grep default
# 例: default via 172.25.208.1 dev eth0 proto kernel

curl http://172.25.208.1:11434/api/tags   # 上で出たIPに置き換える
```

`{"models":[...]}` が返れば疎通OK。`capabilities` に `"tools"` が含まれるモデルを使うこと
(Strix はツール呼び出し=function callingを多用するため)。

それでも繋がらない場合は Windows Defender ファイアウォールの受信ブロックが疑われる。
PowerShell(管理者権限)で許可ルールを追加する:

```powershell
New-NetFirewallRule -DisplayName "Ollama 11434" -Direction Inbound -LocalPort 11434 -Protocol TCP -Action Allow
```

## 3. Strix CLI の導入(WSL側)

Strixのインストーラは bash スクリプトなので、PowerShellではなく **WSL側** で実行する。

```bash
curl -sSL https://strix.ai/install | bash
```

インストール直後は `.bashrc` に PATH 追記のみで、**今開いているシェルには反映されない**。

```bash
source ~/.bashrc
strix --version   # strix 1.7.0 のように出ればOK
```

> 補足: 導入時に一度だけ `curl: (60) SSL: certificate subject name 'NA' does not match target
> hostname` という証明書検証エラーが出ることがあった。再実行で解消した。再発する場合は、
> 社内プロキシやセキュリティソフトのHTTPS検査機能がTLSを中継していないか確認すること。

## 4. Docker Desktop の WSL 統合を確認する

`docker info` が PowerShell 側で通っても、**WSL側のそのディストロに対して WSL Integration が
有効になっていないと** Strix(WSL側プロセス)から Docker デーモンに到達できず、
`DOCKER NOT AVAILABLE` エラーになる。

Docker Desktop → **Settings → Resources → WSL Integration** で、使っているディストロ
(例: Ubuntu)のトグルを ON にし、Apply & Restart する。

WSL側で確認:

```bash
docker info
docker pull ghcr.io/usestrix/strix-sandbox:1.3.0
```

## 5. 環境変数を設定してスキャン実行(WSL側)

```bash
export STRIX_LLM="ollama/qwen2.5:1.5b"
export OLLAMA_API_BASE="http://172.25.208.1:11434"   # 手順2で確認したIPに置き換える
export LLM_API_KEY="dummy"                            # ローカルOllamaは認証不要だが値は必須

# 自分で立てたDVWA(docker run --rm -p 8080:80 vulnerables/web-dvwa)を対象に、
# 軽量モードで実行
strix -n -t http://localhost:8080 --scan-mode quick --max-budget 10
```

結果は `strix_runs/<run-name>/` 以下に `penetration_test_report.md` /
`vulnerabilities.json` / `findings.sarif` として出力される(`AGENTS.md` 記載の仕様)。

## 既知の留意点

- `qwen2.5:1.5b` のような小型モデルは、Strixが要求する複雑なツール呼び出し
  (正確なJSON形式での関数呼び出し、長い推論チェーン)に対して力不足な可能性が高い。
  エージェントループ途中でツール呼び出しの形式を誤って停止することが起こり得る。
  その場合は `ollama pull qwen2.5:7b` 等、もう一段大きいモデルへの切り替えを検討する。
- `STRIX_LLM` は LiteLLM のモデルID形式。`config/settings.py` のエイリアス定義で
  `OLLAMA_API_BASE` が公式にサポートされていることをソースコードで確認済み
  (推測ではない)。
- Docker版バックエンド(既定)を使う場合、ネットワーク系ツール(nmap等)はコンテナ内に
  同梱されているため追加導入は不要。Docker不要の `local` バックエンドを使う場合は
  `strix-local-backend-notes.md` を参照(caido/nmap等は別途ホストへの導入が必要)。

## 未検証(このメモの範囲外)

- 小型ローカルモデルでのスキャン完走、および検出精度。
- `qwen2.5:7b` 以上のモデルでの動作。
