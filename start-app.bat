@echo off
rem MCP Detector - double-click this file to open the app in your browser (Windows).
rem It checks that Node.js is installed, prepares MCP Detector the first time, and starts the app.
rem Nothing here changes your system: it only runs "npm install" and "npm run build" inside this folder.
setlocal
cd /d "%~dp0"
title MCP Detector

where node >nul 2>nul
if errorlevel 1 goto :nonode

node -e "const [a,b]=process.versions.node.split('.').map(Number);process.exit(a>22||(a===22&&b>=12)?0:1)" >nul 2>nul
if errorlevel 1 goto :oldnode

if not exist "node_modules\" (
  echo.
  echo First-time setup: downloading what MCP Detector needs. This takes a minute or two and only happens once.
  echo.
  call npm install --no-audit --no-fund
  if errorlevel 1 goto :failed
)

echo.
echo Preparing MCP Detector...
call npm run build --silent
if errorlevel 1 goto :failed

set "OPENFLAG="
if defined MCPD_NO_OPEN set "OPENFLAG=--no-open"

echo.
node dist\cli\index.js ui %OPENFLAG%
echo.
echo MCP Detector has stopped. You can close this window.
pause
exit /b 0

:nonode
echo.
echo MCP Detector needs a free program called Node.js, and it is not installed on this computer yet.
echo.
echo   1. Your browser will open the download page.
echo   2. Click the big "LTS" download button, run the installer, and accept the defaults.
echo   3. Then double-click start-app.bat again.
echo.
if not defined MCPD_NO_OPEN start "" "https://nodejs.org/en/download"
pause
exit /b 1

:oldnode
echo.
echo Your copy of Node.js is too old. MCP Detector needs version 22.12 or newer.
echo Your version is:
node --version
echo.
echo Download the current "LTS" version from https://nodejs.org/en/download, install it, then double-click start-app.bat again.
if not defined MCPD_NO_OPEN start "" "https://nodejs.org/en/download"
pause
exit /b 1

:failed
echo.
echo Something went wrong while preparing MCP Detector (see the messages above).
echo Most often this is a problem with the internet connection. Check it and try again.
echo If it keeps happening, please report it at https://github.com/adebayomoses/MCP-Doctor/issues and include the text above.
pause
exit /b 1
