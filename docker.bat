@echo off
setlocal

echo.
echo ============================================
echo Starting Vulnerable Server
echo ============================================
echo.
echo Server will be accessible at: http://localhost:80
echo Press Ctrl+C to stop the server
echo.

REM Clean up any existing container
for /f "tokens=*" %%i in ('docker ps -aq -f name=vulnerable-server 2^>nul') do docker rm -f %%i 2>nul

REM Run the server (--rm auto-removes after stop)
docker run --rm -p 80:8080 amarmic/attacks_on_implementations:Assignment1_x86_64

echo.
echo Server stopped.
echo.
