# Get token
$loginResp = Invoke-WebRequest -Uri 'http://localhost:8000/api/v1/auth/login' -Method POST -ContentType 'application/x-www-form-urlencoded' -Body 'username=admin&password=admin123'
$token = ($loginResp.Content | ConvertFrom-Json).access_token

# Call risk-trends
$trendsResp = Invoke-WebRequest -Uri 'http://localhost:8000/api/v1/dashboard/risk-trends?days=3' -Method GET -Headers @{Authorization="Bearer $token"}
Write-Host "Risk Trends:"
Write-Host $trendsResp.Content

# Call endpoint-stats
$endpointResp = Invoke-WebRequest -Uri 'http://localhost:8000/api/v1/dashboard/endpoint-stats' -Method GET -Headers @{Authorization="Bearer $token"}
Write-Host "`nEndpoint Stats:"
Write-Host $endpointResp.Content
