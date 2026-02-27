@echo off
echo ============================================================
echo   Starting Threat Intelligence Platform API Server
echo ============================================================
echo.
echo API Server: http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo.
echo Starting server...
echo.

python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

pause
