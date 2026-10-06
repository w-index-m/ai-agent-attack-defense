#!/usr/bin/env bash
# 隔離ラボでの Cairn 起動ヘルパー（local 実行 / ローカルLLM）。
# 認可済み・隔離済みのホストでのみ実行すること。runbook の実行前チェックリストを満たしてから使う。
set -euo pipefail

CAIRN_DIR="${CAIRN_DIR:-$HOME/Cairn}"          # Cairn のクローン先
CFG="${CFG:-$(cd "$(dirname "$0")" && pwd)/dispatch.lab.yaml}"
TARGET="${TARGET:-10.77.0.10}"                 # 既定の隔離ネットの対象アドレス（自分の所有物）
GOAL="${GOAL:-get a shell}"

cd "$CAIRN_DIR"

echo "[*] 事前チェック: codex CLI が PATH 上にあるか"
command -v codex >/dev/null || { echo "codex CLI が見つかりません（local 実行は host CLI を再利用します）"; exit 1; }

echo "[*] 1) サーバ（黒板）を起動"
UV_DEFAULT_INDEX="https://pypi.org/simple" uv run --project cairn cairn serve --host 127.0.0.1 --port 8000 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 5

echo "[*] 2) プロジェクト作成（origin=認可済みラボ対象, goal）"
curl -s -X POST http://127.0.0.1:8000/projects -H 'Content-Type: application/json' \
  -d "{\"title\":\"lab-run\",\"origin\":\"authorized lab target http://${TARGET}\",\"goal\":\"${GOAL}\",\"bootstrap_enabled\":true}"
echo

echo "[*] 3) ディスパッチャ起動（Ctrl-C で停止）"
UV_DEFAULT_INDEX="https://pypi.org/simple" uv run --project cairn cairn dispatch --config "$CFG"
