@echo off
echo ============================================================
echo   THREAT INTELLIGENCE PLATFORM - COMPLETE TEST SUITE
echo ============================================================
echo.

REM Check Docker services
echo [1/5] Checking Docker services...
docker-compose ps
if errorlevel 1 (
    echo ERROR: Docker services not running
    echo Starting Docker services...
    docker-compose up -d db redis
    timeout /t 5 /nobreak >nul
)
echo.

REM Validate components
echo [2/5] Validating system components...
python quick_test.py
if errorlevel 1 (
    echo ERROR: Component validation failed
    pause
    exit /b 1
)
echo.

REM Start API server in background
echo [3/5] Starting API server...
echo Starting server at http://localhost:8000
echo.
start /B python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > server.log 2>&1

REM Wait for server to start
echo Waiting for server to initialize...
timeout /t 5 /nobreak >nul

REM Run demo test
echo [4/5] Running live demo test...
python demo_test.py
if errorlevel 1 (
    echo ERROR: Demo test failed
    echo Check server.log for details
    pause
    exit /b 1
)
echo.

REM Open test frontend
echo [5/5] Opening test frontend...
echo.
echo ============================================================
echo   OPENING TEST FRONTEND IN BROWSER
echo ============================================================
echo.
echo The test frontend will open in your default browser.
echo You can now test all API endpoints interactively!
echo.
echo API Server: http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo.
echo Press Ctrl+C in the server window to stop the API server.
echo.

start test_frontend.html

echo.
echo ============================================================
echo   TEST SUITE COMPLETE
echo ============================================================
echo.
echo Next steps:
echo   1. Test endpoints in the browser
echo   2. Check server.log for API logs
echo   3. Press Ctrl+C to stop the server when done
echo.
pause
