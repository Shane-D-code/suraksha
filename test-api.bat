@echo off
REM API Testing Script for Threat Intelligence Platform

echo ========================================
echo API Testing Suite
echo ========================================
echo.
echo Make sure the API is running on http://localhost:8000
echo.
pause

echo.
echo [Test 1] Health Check
echo ----------------------------------------
curl -X GET http://localhost:8000/health
echo.
echo.

echo [Test 2] Root Endpoint
echo ----------------------------------------
curl -X GET http://localhost:8000/
echo.
echo.

echo [Test 3] Scan URL - Low Risk
echo ----------------------------------------
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"https://google.com\"}"
echo.
echo.

echo [Test 4] Scan URL - Potential Phishing
echo ----------------------------------------
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"https://phishing.test\"}"
echo.
echo.

echo [Test 5] Scan Text Content
echo ----------------------------------------
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"text\": \"Click here to win $1000000! Enter your password now!\"}"
echo.
echo.

echo [Test 6] Scan with Metadata
echo ----------------------------------------
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"https://example.com\", \"metadata\": {\"source\": \"email\", \"user\": \"test\"}}"
echo.
echo.

echo [Test 7] Submit Feedback
echo ----------------------------------------
curl -X POST http://localhost:8000/api/v1/feedback ^
  -H "Content-Type: application/json" ^
  -d "{\"scan_id\": \"test123\", \"user_flag\": true, \"comment\": \"This is clearly phishing\"}"
echo.
echo.

echo [Test 8] Get Domain Intelligence
echo ----------------------------------------
curl -X GET http://localhost:8000/api/v1/threat-intel/example.com
echo.
echo.

echo [Test 9] Get Domain Intelligence - Malicious
echo ----------------------------------------
curl -X GET http://localhost:8000/api/v1/threat-intel/phishing.test
echo.
echo.

echo [Test 10] Model Health
echo ----------------------------------------
curl -X GET http://localhost:8000/api/v1/model-health
echo.
echo.

echo [Test 11] Invalid URL Test
echo ----------------------------------------
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"not-a-valid-url\"}"
echo.
echo.

echo [Test 12] Empty Request Test
echo ----------------------------------------
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{}"
echo.
echo.

echo [Test 13] Cache Test - Repeat Scan
echo ----------------------------------------
echo First scan:
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"https://cache-test.com\"}"
echo.
echo.
echo Second scan (should be cached):
curl -X POST http://localhost:8000/api/v1/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"https://cache-test.com\"}"
echo.
echo.

echo ========================================
echo API Testing Complete!
echo ========================================
echo.
echo Check the responses above for any errors.
echo All endpoints should return valid JSON responses.
echo ========================================
pause
