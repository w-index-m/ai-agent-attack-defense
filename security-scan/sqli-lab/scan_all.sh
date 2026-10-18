#!/usr/bin/env bash
# Run every registered vulnerability class against vulnerable_app.py's
# endpoints in a single command. Assumes vulnerable_app.py is already
# running on http://127.0.0.1:5000 (python3 vulnerable_app.py &).
set -euo pipefail
cd "$(dirname "$0")"

BASE_URL="${1:-http://127.0.0.1:5000}"

run() {
  local label="$1"
  shift
  echo "=== $label ==="
  python3 auto_vuln_scanner.py "$@" || true
  echo
}

run "SQLi: /login (vulnerable)"    --url "$BASE_URL/login"       --class sqli --baseline username=zzz --baseline password=zzz --fuzz username
run "SQLi: /login_safe (fixed)"    --url "$BASE_URL/login_safe"  --class sqli --baseline username=zzz --baseline password=zzz --fuzz username
run "XSS: /search (vulnerable)"    --url "$BASE_URL/search"      --class xss  --baseline q=zzz --fuzz q
run "XSS: /search_safe (fixed)"    --url "$BASE_URL/search_safe" --class xss  --baseline q=zzz --fuzz q
run "CMDi: /diag (vulnerable)"     --url "$BASE_URL/diag"        --class cmdi --baseline host=zzz --fuzz host
run "CMDi: /diag_safe (fixed)"     --url "$BASE_URL/diag_safe"   --class cmdi --baseline host=zzz --fuzz host
run "Traversal: /file (vulnerable)"      --url "$BASE_URL/file"       --class traversal --baseline name=public.txt --fuzz name
run "Traversal: /file_safe (fixed)"      --url "$BASE_URL/file_safe"  --class traversal --baseline name=public.txt --fuzz name

echo "=== CSRF: /csrf_transfer (vulnerable) ==="
python3 csrf_check.py --url "$BASE_URL" --login-path /csrf_login --transfer-path /csrf_transfer || true
echo

echo "=== CSRF: /csrf_transfer_safe (fixed) ==="
python3 csrf_check.py --url "$BASE_URL" --login-path /csrf_login --transfer-path /csrf_transfer_safe || true
echo
