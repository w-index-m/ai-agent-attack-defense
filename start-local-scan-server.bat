@echo off
rem start-local-scan-server.bat: double-click launcher for scripts\local_scan_server.py.
rem Starts the server from this file's own folder (the repo root), keeping the window
rem open while the server runs (stop with Ctrl+C, or just close the window).
rem
rem Usage: double-click this file. To use a non-default port, make a shortcut to this
rem file and add a space + port number at the end of the shortcut's "Target" field
rem (example: ...\start-local-scan-server.bat 8767).
rem
rem Note: this file is plain ASCII on purpose (no Japanese text) -- Windows cmd.exe can
rem misread non-ASCII characters in a .bat file depending on the active code page,
rem which then breaks command parsing (not just garbled text).

cd /d "%~dp0"

where python3 >nul 2>nul
if %errorlevel%==0 (
  set PY=python3
) else (
  set PY=python
)

if "%~1"=="" (
  echo Starting local_scan_server.py on the default port 8766 ...
  %PY% scripts\local_scan_server.py
) else (
  echo Starting local_scan_server.py on port %1 ...
  %PY% scripts\local_scan_server.py --port %1
)

echo.
echo The server has stopped. If you see an error above, check it for details.
pause
