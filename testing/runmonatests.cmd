@echo off
setlocal EnableExtensions

set DEBUGGER_BASE=C:\Program Files (x86)\Windows Kits\10\Debuggers
set MONA_PATH=C:\Tools\mona3\mona.py
set TARGET_APP_32=C:\Windows\SysWOW64\calc.exe
set TARGET_APP_64=C:\Windows\System32\calc.exe

rem Choose:
rem   windbg  (GUI)
rem   cdb     (console)
rem   windbgx (Preview, launched from PATH)
set DEBUGGER_FRONTEND=windbg

rem Auto-exit debugger after running commands (recommended for cdb)
set AUTO_QUIT=0

rem Keep temp script (set to 1 for debugging)
set KEEP_TEMP=0

if "%~1"=="" goto help

set MONACMD=%*

echo ==================================================
echo            Corelan monav3 tester
echo       (c) 2026 Corelan Consulting bv
echo ==================================================

call :run_py39_32
call :run_py39_64
call :run_py27_32
call :run_py27_64
call :run_windbgx_32
call :run_windbgx_64

goto end


:set_debugger_cmd
call :set_debugger_cmd_for %DEBUGGER_FRONTEND% %~1
exit /b


:set_debugger_cmd_for
if /I "%~1"=="windbgx" (
    set "DEBUGGER_CMD=windbgx.exe"
) else (
    set "DEBUGGER_CMD=%DEBUGGER_BASE%\%~2\%~1.exe"
)
exit /b


:make_script
set WINDBG_SCRIPT=C:\Windows\Temp\mona_windbg_%RANDOM%_%RANDOM%.txt

(
    echo .load pykd
    echo as !mona %~1 %MONA_PATH%
    echo(%MONACMD%
    if "%AUTO_QUIT%"=="1" echo q
) > "%WINDBG_SCRIPT%"

exit /b


:cleanup_script
if "%KEEP_TEMP%"=="1" (
    echo [*] Kept script: %WINDBG_SCRIPT%
) else (
    del "%WINDBG_SCRIPT%" >nul 2>&1
)
exit /b


:run_py39_32
echo.
echo [*] x86 + Python 3.9

call :make_script "!py -3.9"
call :set_debugger_cmd x86
"%DEBUGGER_CMD%" -hd -c "$$<%WINDBG_SCRIPT%" "%TARGET_APP_32%"
call :cleanup_script
exit /b


:run_py39_64
echo.
echo [*] x64 + Python 3.9

call :make_script "!py -3.9"
call :set_debugger_cmd x64
"%DEBUGGER_CMD%" -hd -c "$$<%WINDBG_SCRIPT%" "%TARGET_APP_64%"
call :cleanup_script
exit /b


:run_py27_32
echo.
echo [*] x86 + Python 2.7

set ORIGPATH=%PATH%
set PYTHONHOME=C:\Python27
set PATH=%PYTHONHOME%;%PATH%
set PYTHONPATH=%PYTHONHOME%\Lib

call :make_script "!py -2.7"
call :set_debugger_cmd x86
"%DEBUGGER_CMD%" -hd -c "$$<%WINDBG_SCRIPT%" "%TARGET_APP_32%"
call :cleanup_script

set PATH=%ORIGPATH%
set PYTHONHOME=
set PYTHONPATH=
exit /b


:run_py27_64
echo.
echo [*] x64 + Python 2.7

set ORIGPATH=%PATH%
set PYTHONHOME=C:\Python27-64
set PATH=%PYTHONHOME%;%PATH%
set PYTHONPATH=%PYTHONHOME%\Lib

call :make_script "!py -2.7"
call :set_debugger_cmd x64
"%DEBUGGER_CMD%" -hd -c "$$<%WINDBG_SCRIPT%" "%TARGET_APP_64%"
call :cleanup_script

set PATH=%ORIGPATH%
set PYTHONHOME=
set PYTHONPATH=
exit /b


:run_windbgx_32
echo.
echo [*] x86 + WinDbgX + Python 3.9

call :make_script "!py -3.9"
call :set_debugger_cmd_for windbgx x86
"%DEBUGGER_CMD%" -hd -c "$$<%WINDBG_SCRIPT%" "%TARGET_APP_32%"
call :cleanup_script
exit /b


:run_windbgx_64
echo.
echo [*] x64 + WinDbgX + Python 3.9

call :make_script "!py -3.9"
call :set_debugger_cmd_for windbgx x64
"%DEBUGGER_CMD%" -hd -c "$$<%WINDBG_SCRIPT%" "%TARGET_APP_64%"
call :cleanup_script
exit /b


:help
echo Usage:
echo.
echo   %~nx0 ^<mona command^>
echo.
echo Examples:
echo.
echo   %~nx0 !mona modules
echo   %~nx0 !mona rop -m kernel32.dll
echo   %~nx0 !mona config -set workingfolder c:\logs\%p
echo.
echo Settings inside this file:
echo.
echo   set DEBUGGER_FRONTEND=windbg  (GUI)
echo   set DEBUGGER_FRONTEND=cdb     (console)
echo   set DEBUGGER_FRONTEND=windbgx (Preview from PATH)
echo.
echo   set TARGET_APP_32=C:\Path\To\app32.exe
echo   set TARGET_APP_64=C:\Path\To\app64.exe
echo.
echo   set AUTO_QUIT=1               (auto exit debugger)
echo   set KEEP_TEMP=1               (keep temp script)
echo.

:end
endlocal
