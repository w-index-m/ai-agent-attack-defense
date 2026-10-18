<#
.SYNOPSIS
  Windows側から、ローカルOllama + WSL上のStrixでの脆弱性テストを一括起動するスクリプト。

.DESCRIPTION
  windows-wsl-ollama-setup.md で手動で踏んだ手順(Docker起動確認、Ollama起動確認、
  DVWAコンテナ起動確認、WSL内での環境変数設定とstrix実行)を、PowerShellから一括で
  自動化したもの。対象は自分が所有するローカル環境(DVWA等)に限定すること。

  Windows側から直接 "wsl.exe" を呼ぶ形にしている(Python経由ではない)。WSL上のStrixは
  bashスクリプトとして配布されているため、オーケストレーション自体はPowerShellで行い、
  実行だけをWSL側に委譲するのが素直な構成。

.PARAMETER Target
  スキャン対象URL。既定は自分で立てたDVWA(http://localhost:8080)。

.PARAMETER Model
  使うOllamaモデル名(タグ付き)。既定は qwen2.5:7b (実機検証で1.5bより安定した動きを確認済み)。

.PARAMETER Instruction
  Strixへの--instruction。空なら付けない(オープンな探索に任せる)。

.PARAMETER Headless
  指定すると -n (ヘッドレス)付きで実行する。既定は対話TUI(1ウィンドウでライブビューが
  見られる)。ヘッドレスにした場合、進捗は別ターミナルで `strix view <run-name>` を使う。

.EXAMPLE
  .\start-strix-test.ps1

.EXAMPLE
  .\start-strix-test.ps1 -Model "qwen2.5-coder:7b" -Instruction `
    "This is DVWA. Log in with admin:password, set DVWA Security to Low, then test the SQL Injection page only."
#>

param(
    [string]$Target = "http://localhost:8080",
    [string]$Model = "qwen2.5:7b",
    [string]$Instruction = "",
    [switch]$Headless,
    [string]$DockerDesktopPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe",
    [int]$MaxTurns = 30,
    [int]$MaxBudget = 10
)

$ErrorActionPreference = "Stop"

function Wait-DockerReady {
    Write-Host "[1/4] Dockerの状態を確認しています..."
    $maxWaitSeconds = 90
    $waited = 0
    while ($true) {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "      Docker Desktop は準備完了です。"
            return
        }
        if ($waited -eq 0) {
            if (Test-Path $DockerDesktopPath) {
                Write-Host "      Docker Desktop を起動しています... ($DockerDesktopPath)"
                Start-Process -FilePath $DockerDesktopPath
            } else {
                throw "Docker Desktop の実行ファイルが見つかりません: $DockerDesktopPath `n-DockerDesktopPath で実際のパスを指定してください。"
            }
        }
        Start-Sleep -Seconds 5
        $waited += 5
        if ($waited -ge $maxWaitSeconds) {
            throw "Docker Desktop が $maxWaitSeconds 秒以内に準備完了になりませんでした。手動で起動状態を確認してください。"
        }
    }
}

function Wait-OllamaReady {
    Write-Host "[2/4] Ollamaの状態を確認しています..."
    try {
        Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 2 -ErrorAction Stop | Out-Null
        Write-Host "      Ollama は既に起動しています。"
        return
    } catch {
        Write-Host "      Ollama に接続できません。OLLAMA_HOST=0.0.0.0:11434 で起動を試みます..."
    }

    $env:OLLAMA_HOST = "0.0.0.0:11434"
    Start-Process -FilePath "ollama" -ArgumentList "serve" -WindowStyle Minimized

    $maxWaitSeconds = 30
    $waited = 0
    while ($true) {
        Start-Sleep -Seconds 3
        $waited += 3
        try {
            Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 2 -ErrorAction Stop | Out-Null
            Write-Host "      Ollama が起動しました。"
            return
        } catch {
            if ($waited -ge $maxWaitSeconds) {
                throw "Ollama が $maxWaitSeconds 秒以内に起動しませんでした。OLLAMA_HOST が 0.0.0.0:11434 になっているか、手動で `ollama serve` を実行して確認してください。"
            }
        }
    }
}

function Confirm-Model {
    Write-Host "      モデル '$Model' の有無を確認しています..."
    $tags = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 5
    $found = $tags.models | Where-Object { $_.name -eq $Model }
    if (-not $found) {
        Write-Host "      '$Model' が見つかりません。'ollama pull $Model' を実行します(時間がかかります)..."
        & ollama pull $Model
    } else {
        Write-Host "      '$Model' は導入済みです。"
    }
}

function Confirm-Dvwa {
    Write-Host "[3/4] DVWAコンテナの状態を確認しています..."
    $runningId = (docker ps -q --filter ancestor=vulnerables/web-dvwa)
    if ($runningId) {
        Write-Host "      DVWAは既に起動しています ($runningId)。"
        return
    }
    $existingId = (docker ps -a -q --filter ancestor=vulnerables/web-dvwa | Select-Object -First 1)
    if ($existingId) {
        Write-Host "      停止中のDVWAコンテナを再開します ($existingId)..."
        docker start $existingId | Out-Null
    } else {
        Write-Host "      DVWAコンテナを新規作成します..."
        docker run -d -p 8080:80 vulnerables/web-dvwa | Out-Null
    }
    Start-Sleep -Seconds 3
}

function Get-WslHostIp {
    $ip = (wsl.exe -e bash -lc "ip route show | grep default | awk '{print `$3}'").Trim()
    if (-not $ip) {
        throw "WSL側からWindowsホストのIPを取得できませんでした。'wsl ip route show' を手動で確認してください。"
    }
    return $ip
}

Wait-DockerReady
Wait-OllamaReady
Confirm-Model
Confirm-Dvwa

Write-Host "[4/4] WSL上でStrixを起動します..."
$wslIp = Get-WslHostIp
Write-Host "      WSLから見たWindowsホストIP: $wslIp"

$strixFlags = "--scan-mode quick --max-budget $MaxBudget --max-turns $MaxTurns"
if ($Headless) { $strixFlags = "-n $strixFlags" }

$instructionArg = ""
if ($Instruction -ne "") {
    $escaped = $Instruction -replace '"', '\"'
    $instructionArg = " --instruction `"$escaped`""
}

$remoteCmd = @"
export STRIX_LLM='ollama/$Model'
export OLLAMA_API_BASE='http://$wslIp:11434'
export LLM_API_KEY='dummy'
strix -t '$Target' $strixFlags$instructionArg
"@

Write-Host "------------------------------------------------------------"
Write-Host "WSL内で実行するコマンド:"
Write-Host $remoteCmd
Write-Host "------------------------------------------------------------"

wsl.exe bash -lc "$remoteCmd"
