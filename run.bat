@echo off
rem Secure Repo launcher for Windows (cmd / PowerShell / double click).
rem First run: creates a private virtual environment next to this script and installs Secure Repo.
rem Every argument is forwarded, e.g.:  run.bat scan https://github.com/owner/repo.git
setlocal
set "DIR=%~dp0"

if not exist "%DIR%.venv\Scripts\python.exe" (
  echo [*] First run: creating virtual environment in %DIR%.venv
  py -3 -m venv "%DIR%.venv" 2>nul || python -m venv "%DIR%.venv"
  if not exist "%DIR%.venv\Scripts\python.exe" (
    echo [x] Python 3.9+ is required. Install it from https://www.python.org/downloads/
    exit /b 1
  )
  "%DIR%.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  "%DIR%.venv\Scripts\python.exe" -m pip install --quiet -e "%DIR%."
  echo [+] Secure Repo installed.
)

"%DIR%.venv\Scripts\python.exe" -m secure_repo %*
exit /b %ERRORLEVEL%
