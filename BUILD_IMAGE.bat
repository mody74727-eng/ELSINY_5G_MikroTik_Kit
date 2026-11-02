@echo off
setlocal
cd /d "%~dp0app"
where docker >nul 2>nul
if errorlevel 1 (
  echo Docker Desktop is not installed or not running.
  echo Install Docker Desktop, start it, then run this file again.
  pause
  exit /b 1
)
echo Building ELSINY_5G for MikroTik x86_64 (linux/amd64)...
docker build --platform linux/amd64 -t elsiny_5g:1.0 .
if errorlevel 1 goto failed
echo Exporting image archive...
docker save -o "%~dp0ELSINY_5G_mikrotik.tar" elsiny_5g:1.0
if errorlevel 1 goto failed
echo.
echo SUCCESS: %~dp0ELSINY_5G_mikrotik.tar
echo Upload this TAR file to MikroTik using WinBox Files.
pause
exit /b 0
:failed
echo BUILD FAILED. Copy the error text and send it for diagnosis.
pause
exit /b 1
