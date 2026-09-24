@echo off
for /f "tokens=3" %%a in ('echo') do set "ECHO_STATE=%%a"
set "ECHO_STATE=%ECHO_STATE:.=%"
clang++ -v >nul 2>&1
if errorlevel 1 (
    echo clang++?
    goto end
)
mkdir build >nul 2>&1
clang++ .\src\main.cpp -o .\build\cealer.exe
if errorlevel 1 goto end
:end
if /i "%ECHO_STATE%"=="on" @echo on
