@echo off
REM Comprehensive validation script for Threat Intelligence Platform

echo ========================================
echo System Validation Check
echo ========================================
echo.

set ERROR_COUNT=0

echo [1/10] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python not found
    set /a ERROR_COUNT+=1
) else (
    python --version
    echo [PASS] Python installed
)

echo.
echo [2/10] Checking virtual environment...
if exist venv\Scripts\python.exe (
    echo [PASS] Virtual environment exists
) else (
    echo [FAIL] Virtual environment not found
    set /a ERROR_COUNT+=1
)

echo.
echo [3/10] Checking Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Docker not found
    set /a ERROR_COUNT+=1
) else (
    docker --version
    echo [PASS] Docker installed
)

echo.
echo [4/10] Checking Docker Compose...
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Docker Compose not found
    set /a ERROR_COUNT+=1
) else (
    docker-compose --version
    echo [PASS] Docker Compose installed
)

echo.
echo [5/10] Checking .env file...
if exist .env (
    echo [PASS] .env file exists
) else (
    echo [WARN] .env file not found - will use defaults
)

echo.
echo [6/10] Checking project structure...
set MISSING_DIRS=0
if not exist app\api (
    echo [FAIL] Missing: app\api
    set /a MISSING_DIRS+=1
)
if not exist app\models (
    echo [FAIL] Missing: app\models
    set /a MISSING_DIRS+=1
)
if not exist app\services (
    echo [FAIL] Missing: app\services
    set /a MISSING_DIRS+=1
)
if not exist app\middleware (
    echo [FAIL] Missing: app\middleware
    set /a MISSING_DIRS+=1
)
if not exist app\tasks (
    echo [FAIL] Missing: app\tasks
    set /a MISSING_DIRS+=1
)
if not exist tests (
    echo [FAIL] Missing: tests
    set /a MISSING_DIRS+=1
)

if %MISSING_DIRS%==0 (
    echo [PASS] All directories present
) else (
    echo [FAIL] Missing %MISSING_DIRS% directories
    set /a ERROR_COUNT+=1
)

echo.
echo [7/10] Checking key files...
set MISSING_FILES=0
if not exist app\main.py (
    echo [FAIL] Missing: app\main.py
    set /a MISSING_FILES+=1
)
if not exist app\config.py (
    echo [FAIL] Missing: app\config.py
    set /a MISSING_FILES+=1
)
if not exist requirements.txt (
    echo [FAIL] Missing: requirements.txt
    set /a MISSING_FILES+=1
)
if not exist docker-compose.yml (
    echo [FAIL] Missing: docker-compose.yml
    set /a MISSING_FILES+=1
)
if not exist Dockerfile (
    echo [FAIL] Missing: Dockerfile
    set /a MISSING_FILES+=1
)

if %MISSING_FILES%==0 (
    echo [PASS] All key files present
) else (
    echo [FAIL] Missing %MISSING_FILES% files
    set /a ERROR_COUNT+=1
)

echo.
echo [8/10] Checking Docker services...
docker ps >nul 2>&1
if errorlevel 1 (
    echo [WARN] Docker not running - cannot check services
) else (
    docker ps --format "table {{.Names}}\t{{.Status}}" | findstr "aws_builder"
    if errorlevel 1 (
        echo [WARN] No services running - run: docker-compose up -d
    ) else (
        echo [PASS] Docker services found
    )
)

echo.
echo [9/10] Checking Python dependencies...
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
    python -c "import fastapi, uvicorn, sqlalchemy, redis, networkx" 2>nul
    if errorlevel 1 (
        echo [FAIL] Some dependencies missing
        set /a ERROR_COUNT+=1
    ) else (
        echo [PASS] Core dependencies installed
    )
) else (
    echo [SKIP] Virtual environment not found
)

echo.
echo [10/10] Checking API endpoints (if running)...
curl -s http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    echo [WARN] API not running - start with: run.bat
) else (
    echo [PASS] API is responding
    curl -s http://localhost:8000/health
)

echo.
echo ========================================
echo Validation Summary
echo ========================================
if %ERROR_COUNT%==0 (
    echo [SUCCESS] All critical checks passed!
    echo.
    echo Ready to run:
    echo   - Start services: docker-compose up -d
    echo   - Run API: run.bat
    echo   - Run tests: test.bat
) else (
    echo [FAILED] %ERROR_COUNT% critical issues found
    echo.
    echo Please fix the issues above before proceeding.
    echo Run setup.bat to initialize the project.
)
echo ========================================
