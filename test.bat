@echo off
REM Test script for Threat Intelligence Platform

echo ========================================
echo Running Tests
echo ========================================
echo.

REM Activate virtual environment
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
) else (
    echo ERROR: Virtual environment not found. Run setup.bat first.
    exit /b 1
)

echo [1/3] Running unit tests...
pytest tests/ -v --tb=short

echo.
echo [2/3] Running code quality checks...
echo Checking with flake8...
flake8 app/ --count --select=E9,F63,F7,F82 --show-source --statistics

echo.
echo [3/3] Checking code formatting...
echo Checking with black...
black --check app/ tests/

echo.
echo ========================================
echo Tests complete!
echo ========================================
