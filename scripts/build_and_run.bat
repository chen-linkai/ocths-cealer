@echo off
for /f "tokens=3" %%a in ('echo') do set "ECHO_STATE=%%a"
set "ECHO_STATE=%ECHO_STATE:.=%"
call .\scripts\build.bat
if errorlevel 1 goto end
if exist ".\build\cealer.exe" .\build\cealer.exe
:end
if /i "%ECHO_STATE%"=="on" @echo on
