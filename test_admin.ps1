$token = (Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -ContentType "application/x-www-form-urlencoded" -Body "username=admin&password=admin123").access_token
Write-Host "Token: $token"
$result = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/overrides" -Method GET -Headers @{Authorization="Bearer $token"}
$result | ConvertTo-Json -Depth 10
