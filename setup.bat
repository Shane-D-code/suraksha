@echo off
REM Setup and run script for Threat Intelligence Platform

echo ========================================
echo Threat Intelligence Platform Setup
echo ========================================
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    exit /b 1
)

echo [1/6] Creating virtual environment...
if not exist venv (
    python -m venv venv
    echo Virtual environment created
) else (
    echo Virtual environment already exists
)

echo.
echo [2/6] Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo [3/6] Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo.
echo [4/6] Checking .env file...
if not exist .env (
    echo Creating .env from .env.example...
    copy .env.example .env
) else (
    echo .env file already exists
)

echo.
echo [5/6] Checking Docker services...
docker ps >nul 2>&1
if errorlevel 1 (
    echo WARNING: Docker is not running. Please start Docker Desktop.
    echo You can start services manually with: docker-compose up -d
) else (
    echo Starting Docker services...
    docker-compose up -d db redis
    echo Waiting for services to be ready...
    timeout /t 5 /nobreak >nul
)

echo.
echo [6/6] Setup complete!
echo.
echo ========================================
echo To start the application:
echo   1. Ensure Docker services are running: docker-compose up -d
echo   2. Run: python -m uvicorn app.main:app --reload
echo.
echo Or use: docker-compose up
echo ========================================
echo.
echo API will be available at: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo ========================================
