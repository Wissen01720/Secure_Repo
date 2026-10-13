@echo off
rem Secure Repo launcher for Windows (cmd / PowerShell / double click).
rem First run: creates a private virtual environment next to this script and installs Secure Repo.
rem The environment is only trusted once the file .venv\.installed exists, and that file is written only after
rem every install step succeeded; a failed first run is retried on the next launch instead of leaving a broken setup.
rem Every argument is forwarded, e.g.:  run.bat scan https://github.com/owner/repo.git
setlocal
set "DIR=%~dp0"
set "VENV=%DIR%.venv"

if exist "%VENV%\.installed" goto :run

echo [*] First run: preparing the virtual environment in %VENV%
if not exist "%VENV%\Scripts\python.exe" (
  py -3 -m venv "%VENV%" 2>nul || python -m venv "%VENV%"
)
if not exist "%VENV%\Scripts\python.exe" (
  echo [x] Python 3.9+ is required. Install it from https://www.python.org/downloads/
  exit /b 1
)
rem Dependencies come from the hashed lock file; the project itself is installed editable so updates apply live.
"%VENV%\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check --require-hashes -r "%DIR%requirements.lock"
if errorlevel 1 goto :failed
"%VENV%\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check --no-deps -e "%DIR%."
if errorlevel 1 goto :failed
echo installed> "%VENV%\.installed"
echo [+] Secure Repo installed.

:run
"%VENV%\Scripts\python.exe" -m secure_repo %*
exit /b %ERRORLEVEL%

:failed
echo [x] The installation failed (see the message above). Check your network connection and run this script again.
exit /b 1
