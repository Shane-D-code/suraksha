@echo off
echo Starting Threat Intelligence Platform API Server...
echo.
echo API: http://localhost:8000
echo Docs: http://localhost:8000/docs
echo.

python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
