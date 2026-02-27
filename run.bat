@echo off
REM Quick run script for Threat Intelligence Platform

echo Starting Threat Intelligence Platform...
echo.

REM Activate virtual environment
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
) else (
    echo ERROR: Virtual environment not found. Run setup.bat first.
    exit /b 1
)

REM Check if Docker services are running
docker ps >nul 2>&1
if errorlevel 1 (
    echo WARNING: Docker is not running. Starting services...
    docker-compose up -d db redis
    timeout /t 5 /nobreak >nul
)

echo.
echo Starting FastAPI server...
echo API: http://localhost:8000
echo Docs: http://localhost:8000/docs
echo.

python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
