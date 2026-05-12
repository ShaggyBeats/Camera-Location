@echo off
cd /d "%~dp0"
SET ELECTRON="%~dp0node_modules\electron\dist\electron.exe"

if not exist %ELECTRON% (
    echo Electron not found. Running npm install first...
    SET "PATH=C:\Program Files\nodejs;%PATH%"
    call npm install --ignore-scripts
)

echo Starting Camera Discovery Octopus...
start "" %ELECTRON% .
