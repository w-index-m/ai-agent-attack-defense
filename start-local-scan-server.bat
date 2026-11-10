@echo off
rem start-local-scan-server.bat: scripts\local_scan_server.py を、このファイルがある
rem リポジトリのルートから起動する(ダブルクリック用)。ウィンドウはサーバーが動いて
rem いる間ずっと開いたままになる(終了するにはCtrl+Cか、ウィンドウを閉じる)。
rem
rem 使い方: このファイルをダブルクリックするだけ。
rem 既定ポート以外を使いたい場合は、このファイルにショートカットを作り、「リンク先」の
rem 末尾に半角スペース + ポート番号を追加する(例: ...\start-local-scan-server.bat 8767)。

cd /d "%~dp0"

where python3 >nul 2>nul
if %errorlevel%==0 (
  set PY=python3
) else (
  set PY=python
)

if "%~1"=="" (
  echo local_scan_server.py を既定ポート(8766)で起動します...
  %PY% scripts\local_scan_server.py
) else (
  echo local_scan_server.py をポート %1 で起動します...
  %PY% scripts\local_scan_server.py --port %1
)

echo.
echo サーバーが終了しました(エラーが出ている場合は、上のメッセージを確認してください)。
pause
