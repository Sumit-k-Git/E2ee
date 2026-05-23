@echo off
:: vault.msg — start-local.bat
:: Double-click this file on Windows to start the app.
:: Requires Node.js 18+ from https://nodejs.org

setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo  ======================================
echo   vault.msg - Starting locally
echo  ======================================
echo.

:: Check Node.js
where node >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Node.js not found.
    echo.
    echo  Download and install it from: https://nodejs.org
    echo  Choose the LTS version, run the installer, then
    echo  double-click this file again.
    echo.
    pause
    exit /b 1
)

for /f "tokens=1 delims=." %%v in ('node -e "process.stdout.write(process.versions.node)"') do set NODE_MAJOR=%%v
if %NODE_MAJOR% LSS 18 (
    echo  ERROR: Node.js 18+ required. You have:
    node --version
    echo  Download from https://nodejs.org
    pause
    exit /b 1
)

echo  [ok] Node.js found
node --version

:: Install server dependencies
echo.
echo  [..] Installing server packages...
cd server
call npm install
if errorlevel 1 (
    echo  ERROR: npm install failed in server folder.
    pause
    exit /b 1
)
cd ..
echo  [ok] Server packages ready

:: Install client dependencies
echo.
echo  [..] Installing client packages...
cd client
call npm install
if errorlevel 1 (
    echo  ERROR: npm install failed in client folder.
    pause
    exit /b 1
)
cd ..
echo  [ok] Client packages ready

:: Setup .env files
if not exist "server\.env" (
    copy "server\.env.example" "server\.env" >nul
    echo  [ok] Created server\.env
)
if not exist "client\.env" (
    copy "client\.env.example" "client\.env" >nul
    echo  [ok] Created client\.env
)

:: Auto-generate JWT secrets
node -e "
const fs = require('fs');
const crypto = require('crypto');
const gen = () => crypto.randomBytes(64).toString('hex');
const file = 'server\\.env';
let env = fs.readFileSync(file, 'utf8');
let changed = false;
for (const key of ['JWT_SECRET','JWT_REFRESH_SECRET','OTP_SECRET']) {
  const pat = new RegExp('^' + key + '=\\\\s*$', 'm');
  if (pat.test(env)) { env = env.replace(pat, key + '=' + gen()); changed = true; }
}
if (changed) { fs.writeFileSync(file, env); console.log('  [ok] JWT secrets generated'); }
else { console.log('  [ok] Secrets already configured'); }
"

echo.
echo  [..] Starting backend server...
echo  (A new window will open for the server)
echo.

:: Start server in a new window
start "vault.msg Server" cmd /k "cd /d "%~dp0server" && node index.js"

:: Wait for server to be ready
echo  Waiting for server to start...
:wait_loop
timeout /t 2 /nobreak >nul
curl -sf http://localhost:4000/api/health >nul 2>&1
if errorlevel 1 goto wait_loop
echo  [ok] Server is ready!

echo.
echo  [..] Starting frontend...
echo  (Another window will open for the frontend)
echo.

:: Start client in a new window
start "vault.msg Frontend" cmd /k "cd /d "%~dp0client" && npm run dev"

:: Wait for Vite to start
timeout /t 4 /nobreak >nul

:: Open browser
echo.
echo  ======================================
echo   vault.msg is running!
echo  ======================================
echo.
echo   Open in browser: http://localhost:5173
echo.
echo   Sign-up OTP codes appear in the
echo   "vault.msg Server" window.
echo   Look for the === box with your code.
echo.
echo   Close the Server and Frontend windows
echo   to stop the app.
echo.
start "" "http://localhost:5173"
pause
