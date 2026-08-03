@echo off
chcp 65001 >nul
setlocal

set APP_NAME=HeartbleedCamOver2
set PY_FILE=heartbleed_camover_gui.py

set PYTHON=python
where py >nul 2>nul
if %ERRORLEVEL%==0 set PYTHON=py -3

echo [1/3] Installing dependencies...
%PYTHON% -m pip install --upgrade pip
%PYTHON% -m pip install --upgrade customtkinter requests shodan pyinstaller

echo [2/3] Building Windows EXE...
%PYTHON% -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --noconsole ^
  --name "%APP_NAME%" ^
  --collect-all customtkinter ^
  --collect-all requests ^
  --collect-all shodan ^
  --hidden-import=requests ^
  --hidden-import=shodan ^
  --hidden-import=urllib3 ^
  --hidden-import=customtkinter ^
  "%PY_FILE%"

if errorlevel 1 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)

echo.
echo [3/3] Done.
echo Result: dist\%APP_NAME%.exe
pause