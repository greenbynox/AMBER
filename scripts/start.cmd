@echo off
setlocal
set ROOT=%~dp0..
set LOG=%ROOT%\logs\ember-start.log
if not exist "%ROOT%\logs" mkdir "%ROOT%\logs"
echo Starting EMBER... > "%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" -LogPath "%LOG%"
echo.
echo See log: %LOG%
pause
