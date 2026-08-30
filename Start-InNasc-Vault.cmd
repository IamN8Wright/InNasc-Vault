@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Start-InNasc-Vault.ps1"
if errorlevel 1 (
  echo.
  echo InNasc Vault did not start. Review the message above.
  pause
)
