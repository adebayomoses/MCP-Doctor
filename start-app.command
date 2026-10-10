#!/bin/bash
# MCP Detector - double-click this file to open the app in your browser (macOS).
# On Linux, run:  bash start-app.command
# It checks that Node.js is installed, prepares MCP Detector the first time, and starts the app.
# Nothing here changes your system: it only runs "npm install" and "npm run build" inside this folder.

cd "$(dirname "$0")" || exit 1

pause() { echo; read -r -p "Press Enter to close this window..." _; }

if ! command -v node >/dev/null 2>&1; then
  echo
  echo "MCP Detector needs a free program called Node.js, and it is not installed on this computer yet."
  echo
  echo "  1. Open https://nodejs.org/en/download"
  echo "  2. Click the big \"LTS\" download button, run the installer, and accept the defaults."
  echo "  3. Then double-click start-app.command again."
  [ -z "$MCPD_NO_OPEN" ] && command -v open >/dev/null 2>&1 && open "https://nodejs.org/en/download"
  pause; exit 1
fi

if ! node -e "const [a,b]=process.versions.node.split('.').map(Number);process.exit(a>22||(a===22&&b>=12)?0:1)"; then
  echo
  echo "Your copy of Node.js is too old (it is $(node --version)). MCP Detector needs version 22.12 or newer."
  echo "Download the current \"LTS\" version from https://nodejs.org/en/download, install it, then try again."
  [ -z "$MCPD_NO_OPEN" ] && command -v open >/dev/null 2>&1 && open "https://nodejs.org/en/download"
  pause; exit 1
fi

fail() {
  echo
  echo "Something went wrong while preparing MCP Detector (see the messages above)."
  echo "Most often this is a problem with the internet connection. Check it and try again."
  echo "If it keeps happening, please report it at https://github.com/adebayomoses/MCP-Doctor/issues and include the text above."
  pause; exit 1
}

if [ ! -d node_modules ]; then
  echo
  echo "First-time setup: downloading what MCP Detector needs. This takes a minute or two and only happens once."
  echo
  npm install --no-audit --no-fund || fail
fi

echo
echo "Preparing MCP Detector..."
npm run build --silent || fail

echo
if [ -n "$MCPD_NO_OPEN" ]; then node dist/cli/index.js ui --no-open; else node dist/cli/index.js ui; fi

echo
echo "MCP Detector has stopped. You can close this window."
pause
