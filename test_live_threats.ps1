# Get token
$login = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -ContentType "application/x-www-form-urlencoded" -Body "username=admin&password=admin123"
$token = $login.access_token

# Get live threats
$threats = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/dashboard/live-threats?limit=5" -Headers @{"Authorization"="Bearer $token"}

# Output
$threats | ConvertTo-Json -Depth 3
