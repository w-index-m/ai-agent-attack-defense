#!/usr/bin/env bash
# Run every registered vulnerability class against vulnerable_app.py's
# endpoints in a single command. Assumes vulnerable_app.py is already
# running on http://127.0.0.1:5000 (python3 vulnerable_app.py &).
set -euo pipefail
cd "$(dirname "$0")"

BASE_URL="${1:-http://127.0.0.1:${VULN_APP_PORT:-5000}}"

run() {
  local label="$1"
  shift
  echo "=== $label ==="
  python3 auto_vuln_scanner.py "$@" || true
  echo
}

run "SQLi: /login (vulnerable)"    --url "$BASE_URL/login"       --class sqli --baseline username=zzz --baseline password=zzz --fuzz username
run "SQLi: /login_safe (fixed)"    --url "$BASE_URL/login_safe"  --class sqli --baseline username=zzz --baseline password=zzz --fuzz username
run "SQLi (blind/time): /login (vulnerable)"    --url "$BASE_URL/login"       --class sqli_blind_time --baseline username=zzz --baseline password=zzz --fuzz username
run "SQLi (blind/time): /login_safe (fixed)"    --url "$BASE_URL/login_safe"  --class sqli_blind_time --baseline username=zzz --baseline password=zzz --fuzz username
run "SQLi (blind/boolean): /user_exists (vulnerable)"    --url "$BASE_URL/user_exists"       --class sqli_blind_boolean --baseline username=zzz --fuzz username
run "SQLi (blind/boolean): /user_exists_safe (fixed)"    --url "$BASE_URL/user_exists_safe"  --class sqli_blind_boolean --baseline username=zzz --fuzz username
run "XSS: /search (vulnerable)"    --url "$BASE_URL/search"      --class xss  --baseline q=zzz --fuzz q
run "XSS: /search_safe (fixed)"    --url "$BASE_URL/search_safe" --class xss  --baseline q=zzz --fuzz q
run "CMDi: /diag (vulnerable)"     --url "$BASE_URL/diag"        --class cmdi --baseline host=zzz --fuzz host
run "CMDi: /diag_safe (fixed)"     --url "$BASE_URL/diag_safe"   --class cmdi --baseline host=zzz --fuzz host
run "Traversal: /file (vulnerable)"      --url "$BASE_URL/file"       --class traversal --baseline name=public.txt --fuzz name
run "Traversal: /file_safe (fixed)"      --url "$BASE_URL/file_safe"  --class traversal --baseline name=public.txt --fuzz name
run "Mass Assignment: /signup (vulnerable)"      --url "$BASE_URL/signup"      --class mass_assignment --baseline username=zzz --fuzz is_admin
run "Mass Assignment: /signup_safe (fixed)"      --url "$BASE_URL/signup_safe" --class mass_assignment --baseline username=zzz --fuzz is_admin
run "SSRF: /fetch_url (vulnerable)"      --url "$BASE_URL/fetch_url"      --class ssrf --baseline url=https://example.invalid/ --fuzz url
run "SSRF: /fetch_url_safe (fixed)"      --url "$BASE_URL/fetch_url_safe" --class ssrf --baseline url=https://example.invalid/ --fuzz url
run "Account Enum: /register (vulnerable)"      --url "$BASE_URL/register"      --class account_enum --baseline email=brand-new-unused@example.com --fuzz email
run "Account Enum: /register_safe (fixed)"      --url "$BASE_URL/register_safe" --class account_enum --baseline email=brand-new-unused2@example.com --fuzz email
run "HTTP Header Injection: /header_inject (vulnerable)"      --url "$BASE_URL/header_inject"      --class header_injection --fuzz next
run "HTTP Header Injection: /header_inject_safe (fixed)"      --url "$BASE_URL/header_inject_safe" --class header_injection --fuzz next
run "Mail Header Injection: /contact (vulnerable)"      --url "$BASE_URL/contact"      --class mail_header_injection --baseline subject=Hello --baseline body="Hi there" --fuzz to
run "Mail Header Injection: /contact_safe (fixed)"      --url "$BASE_URL/contact_safe" --class mail_header_injection --baseline subject=Hello --baseline body="Hi there" --fuzz to
run "Clickjacking: /dashboard (vulnerable)"      --url "$BASE_URL/dashboard"      --class clickjacking --fuzz dummy
run "Clickjacking: /dashboard_safe (fixed)"      --url "$BASE_URL/dashboard_safe" --class clickjacking --fuzz dummy

echo "=== CSRF: /csrf_transfer (vulnerable) ==="
python3 session_vuln_check.py --class csrf --url "$BASE_URL" --transfer-path /csrf_transfer || true
echo

echo "=== CSRF: /csrf_transfer_safe (fixed) ==="
python3 session_vuln_check.py --class csrf --url "$BASE_URL" --transfer-path /csrf_transfer_safe || true
echo

echo "=== IDOR/BOLA: /idor_account (vulnerable) ==="
python3 session_vuln_check.py --class idor --url "$BASE_URL" --account-path /idor_account || true
echo

echo "=== IDOR/BOLA: /idor_account_safe (fixed) ==="
python3 session_vuln_check.py --class idor --url "$BASE_URL" --account-path /idor_account_safe || true
echo

echo "=== Deserialization RCE: /deserialize (vulnerable) ==="
python3 session_vuln_check.py --class deserialize --url "$BASE_URL" --deserialize-path /deserialize || true
echo

echo "=== Deserialization RCE: /deserialize_safe (fixed) ==="
python3 session_vuln_check.py --class deserialize --url "$BASE_URL" --deserialize-path /deserialize_safe || true
echo

echo "=== Stored XSS: /reviews (vulnerable) ==="
python3 session_vuln_check.py --class stored_xss --url "$BASE_URL" --post-path /review --list-path /reviews || true
echo

echo "=== Stored XSS: /reviews_safe (fixed) ==="
python3 session_vuln_check.py --class stored_xss --url "$BASE_URL" --post-path /review_safe --list-path /reviews_safe || true
echo

echo "=== Second-order SQLi: /second_order_audit (vulnerable) ==="
python3 session_vuln_check.py --class second_order_sqli --url "$BASE_URL" --second-order-signup-path /second_order_signup --second-order-audit-path /second_order_audit || true
echo

echo "=== Second-order SQLi: /second_order_audit_safe (fixed) ==="
python3 session_vuln_check.py --class second_order_sqli --url "$BASE_URL" --second-order-signup-path /second_order_signup_safe --second-order-audit-path /second_order_audit_safe || true
echo

echo "=== BFLA: /admin_secrets (vulnerable) ==="
python3 session_vuln_check.py --class bfla --url "$BASE_URL" --admin-path /admin_secrets || true
echo

echo "=== BFLA: /admin_secrets_safe (fixed) ==="
python3 session_vuln_check.py --class bfla --url "$BASE_URL" --admin-path /admin_secrets_safe || true
echo

echo "=== Session Fixation: /fixation_login (vulnerable) ==="
python3 session_vuln_check.py --class session_fixation --url "$BASE_URL" --fixation-login-path /fixation_login --fixation-whoami-path /fixation_whoami || true
echo

echo "=== Session Fixation: /fixation_login_safe (fixed) ==="
python3 session_vuln_check.py --class session_fixation --url "$BASE_URL" --fixation-login-path /fixation_login_safe --fixation-whoami-path /fixation_whoami_safe || true
echo
