    @echo off
setlocal

echo ==========================================
echo Building System Info Binaries
echo ==========================================

REM -----------------------------
REM Build Windows EXE
REM -----------------------------
echo [1/2] Building Windows executable...

go build -o build/sentinel_windows.exe
if %ERRORLEVEL% neq 0 (
    echo ERROR: Windows build failed!
    pause
    exit /b 1
)

echo   Windows build complete: system-info-windows.exe


REM -----------------------------
REM Build Linux Binary
REM -----------------------------
echo.
echo [2/2] Building Linux executable (Ubuntu + CentOS)...

set GOOS=linux
set GOARCH=amd64

go build -o build/sentinel_linux
if %ERRORLEVEL% neq 0 (
    echo ERROR: Linux build failed!
    pause
    exit /b 1
)

echo   Linux build complete: system-info-linux

REM Reset GOOS/GOARCH
set GOOS=
set GOARCH=

echo.
echo ==========================================
echo Build completed successfully!
echo ==========================================
echo.
echo Files generated:
echo   - sentinel_windows.exe
echo   - sentinel_linux
echo.
pause
endlocal
