@echo off
setlocal

set "PROJ_DIR=%~dp0"

echo ========================================
echo  DES-RSA Encrypted Communication
echo  Build Script for Windows
echo ========================================
echo.

set "SRC_DIR=%PROJ_DIR%src"
set "OUT_DIR=%PROJ_DIR%"

echo [1/2] Compiling server.exe...
g++ -std=c++11 -Wall -I"%SRC_DIR%" -o "%OUT_DIR%server.exe" "%SRC_DIR%\server.cpp" "%SRC_DIR%\des.cpp" "%SRC_DIR%\rsa.cpp" -lws2_32 -lpthread

if %errorlevel% neq 0 (
    echo Error: Server compilation failed!
    exit /b 1
)
echo      Server compilation successful!
echo.

echo [2/2] Compiling client.exe...
g++ -std=c++11 -Wall -I"%SRC_DIR%" -o "%OUT_DIR%client.exe" "%SRC_DIR%\client.cpp" "%SRC_DIR%\des.cpp" "%SRC_DIR%\rsa.cpp" -lws2_32 -lpthread

if %errorlevel% neq 0 (
    echo Error: Client compilation failed!
    exit /b 1
)
echo      Client compilation successful!
echo.

echo ========================================
echo  Build completed successfully!
echo  - server.exe
echo  - client.exe
echo ========================================

endlocal
